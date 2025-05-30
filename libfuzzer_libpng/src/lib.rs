//! A libfuzzer-like fuzzer with llmp-multithreading support and restarts
//! The example harness is built for libpng.
use core::time::Duration;
#[cfg(feature = "crash")]
use std::ptr;
use std::{collections::{HashMap, HashSet}, env, path::PathBuf};

mod test_stage;

use libafl::{
    corpus::{Corpus, InMemoryCorpus, OnDiskCorpus},
    events::{setup_restarting_mgr_std, EventConfig, EventRestarter},
    executors::{inprocess::InProcessExecutor, ExitKind},
    feedback_or, feedback_or_fast,
    feedbacks::{CrashFeedback, MaxMapFeedback, TimeFeedback, TimeoutFeedback},
    fuzzer::{Fuzzer, StdFuzzer},
    inputs::{BytesInput, HasTargetBytes},
    monitors::{MultiMonitor, PrometheusMonitor},
    mutators::{
        havoc_mutations::havoc_mutations,
        scheduled::{tokens_mutations, StdScheduledMutator},
        token_mutations::Tokens,
    },
    observers::{CanTrack, HitcountsMapObserver, StdMapObserver, TimeObserver},
    schedulers::{
        powersched::PowerSchedule, testcase_score::CorpusPowerTestcaseScore, IndexesLenTimeMinimizerScheduler, StdWeightedScheduler
    },
    stages::calibrate::CalibrationStage,
    state::{HasCorpus, StdState},
    Error, HasMetadata
};
use libafl_bolts::{
    rands::StdRand, 
    serdeany::RegistryBuilder, 
    tuples::{tuple_list, Merge}, 
    AsSlice, 
    SerdeAny,

};

use libafl_targets::{libfuzzer_initialize, libfuzzer_test_one_input, EDGES_MAP, MAX_EDGES_FOUND};
use mimalloc::MiMalloc;
use test_stage::TestStage;
use serde::{Serialize, Deserialize};

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

#[derive(Debug, Serialize, Deserialize, SerdeAny)]
pub struct SeenTestCases {
    tescases: HashSet<Vec<u8>>,
    index_to_values: HashMap<usize, HashSet<u8>>,
}

impl SeenTestCases
where {

    pub fn new () -> Self {
        Self { tescases: HashSet::new(), index_to_values: HashMap::new()}
    }

    pub fn testcases_mut(&mut self) -> &mut HashSet<Vec<u8>> {
        &mut self.tescases
    }

    pub fn index_to_value_map_mut(&mut self) -> &mut HashMap<usize, HashSet<u8>> {
        &mut self.index_to_values
    }
}


/// The main fn, `no_mangle` as it is a C main
#[no_mangle]
pub extern "C" fn libafl_main() {
    // Registry the metadata types used in this fuzzer
    // Needed only on no_std
    // unsafe { RegistryBuilder::register::<Tokens>(); }
    
    unsafe {RegistryBuilder::register::<SeenTestCases>();}

    println!(
        "Workdir: {:?}",
        env::current_dir().unwrap().to_string_lossy().to_string()
    );
    fuzz(
        &[PathBuf::from("./corpus")],
        PathBuf::from("./crashes"),
        1337,
    )
    .expect("An error occurred while fuzzing");
}

/// The actual fuzzer
fn fuzz(corpus_dirs: &[PathBuf], objective_dir: PathBuf, broker_port: u16) -> Result<(), Error> {
    // 'While the stats are state, they are usually used in the broker - which is likely never restarted
    let mon = PrometheusMonitor::new("0.0.0.0:8080".to_string(), |s| log::info!("{s}"));
    let multi = MultiMonitor::new(|s| println!("{s}"));
    let monitor = tuple_list!(mon, multi);


    // The restarting state will spawn the same process again as child, then restarted it each time it crashes.
    let (state, mut restarting_mgr) =
        match setup_restarting_mgr_std(monitor, broker_port, EventConfig::AlwaysUnique) {
            Ok(res) => res,
            Err(err) => match err {
                Error::ShuttingDown => {
                    return Ok(());
                }
                _ => {
                    panic!("Failed to setup the restarter: {err}");
                }
            },
        };

    // Create an observation channel using the coverage map
    // TODO: This will break soon, fix me! See https://github.com/AFLplusplus/LibAFL/issues/2786
    #[allow(static_mut_refs)] // only a problem on nightly
    let edges_observer = unsafe {
        HitcountsMapObserver::new(StdMapObserver::from_mut_ptr(
            "edges",
            EDGES_MAP.as_mut_ptr(),
            MAX_EDGES_FOUND,
        ))
        .track_indices()
    };

    // Create an observation channel to keep track of the execution time
    let time_observer = TimeObserver::new("time");

    let max_map_feedback = MaxMapFeedback::new(&edges_observer);

    let calibration = CalibrationStage::new(&max_map_feedback);

    // Feedback to rate the interestingness of an input
    // This one is composed by two Feedbacks in OR
    let mut feedback = feedback_or!(
        // New maximization map feedback linked to the edges observer and the feedback state
        max_map_feedback,
        // Time feedback, this one does not need a feedback state
        TimeFeedback::new(&time_observer)
    );

    // A feedback to choose if an input is a solution or not
    let mut objective = feedback_or_fast!(CrashFeedback::new(), TimeoutFeedback::new());

    // If not restarting, create a State from scratch
    let mut state = state.unwrap_or_else(|| {
        StdState::new(
            // RNG
            StdRand::new(),
            // Corpus that will be evolved, we keep it in memory for performance
            InMemoryCorpus::new(),
            // Corpus in which we store solutions (crashes in this example),
            // on disk so the user can get them after stopping the fuzzer
            OnDiskCorpus::new(objective_dir).unwrap(),
            // States of the feedbacks.
            // The feedbacks can report the data that should persist in the State.
            &mut feedback,
            // Same for objective feedbacks
            &mut objective,
        )
        .unwrap()
    });


    println!("We're a client, let's fuzz :)");

    // add and initialize needed metadata
    state.add_metadata(SeenTestCases::new());
    if state.metadata_map().get::<Tokens>().is_none() {
        state.add_metadata(Tokens::new());
    };


    // Setup a basic mutator with a mutational stage

    let mutator = StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));

    let test_stage:TestStage<_, _, BytesInput, _, _, CorpusPowerTestcaseScore, _, _, _> 
        = TestStage::new(mutator, &edges_observer);

    let mut stages = tuple_list!(calibration, test_stage);

    // A minimization+queue policy to get testcasess from the corpus
    let scheduler = IndexesLenTimeMinimizerScheduler::new(
        &edges_observer,
        StdWeightedScheduler::with_schedule(
            &mut state,
            &edges_observer,
            Some(PowerSchedule::fast()),
        ),
    );

    // A fuzzer with feedbacks and a corpus scheduler
    let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

    // The wrapped harness function, calling out to the LLVM-style harness
    let mut harness = |input: &BytesInput| {
        let target = input.target_bytes();
        let buf = target.as_slice();
        #[cfg(feature = "crash")]
        if buf.len() > 4 && buf[4] == 0 {
            unsafe {
                eprintln!("Crashing (for testing purposes)");
                let addr = ptr::null_mut();
                *addr = 1;
            }
        }
        unsafe {
            libfuzzer_test_one_input(buf);
        }
        ExitKind::Ok
    };

    // Create the executor for an in-process function with one observer for edge coverage and one for the execution time
    let mut executor = InProcessExecutor::with_timeout(
        &mut harness,
        tuple_list!(edges_observer, time_observer),
        &mut fuzzer,
        &mut state,
        &mut restarting_mgr,
        Duration::new(10, 0),
    )?;
    // 10 seconds timeout

    // The actual target run starts here.
    // Call LLVMFUzzerInitialize() if present.
    let args: Vec<String> = env::args().collect();
    if unsafe { libfuzzer_initialize(&args) } == -1 {
        println!("Warning: LLVMFuzzerInitialize failed with -1");
    }

    // In case the corpus is empty (on first run), reset
    if state.must_load_initial_inputs() {
        state
            .load_initial_inputs(&mut fuzzer, &mut executor, &mut restarting_mgr, corpus_dirs)
            .unwrap_or_else(|_| panic!("Failed to load initial corpus at {:?}", &corpus_dirs));
        println!("We imported {} inputs from disk.", state.corpus().count());
    }

    // This fuzzer restarts after 1 mio `fuzz_one` executions.
    // Each fuzz_one will internally do many executions of the target.
    // If your target is very instable, setting a low count here may help.
    // However, you will lose a lot of performance that way.
    let iters = 1_000_000;
    fuzzer.fuzz_loop_for(
        &mut stages,
        &mut executor,
        &mut state,
        &mut restarting_mgr,
        iters,
    )?;

    // It's important, that we store the state before restarting!
    // Else, the parent will not respawn a new child and quit.
    restarting_mgr.on_restart(&mut state)?;

    Ok(())
}
