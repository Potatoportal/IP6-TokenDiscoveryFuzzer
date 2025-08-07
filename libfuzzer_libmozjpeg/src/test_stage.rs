use std::{borrow::Cow, collections::HashSet, marker::PhantomData};

use libafl::{
    corpus::{Corpus, CorpusId, HasCurrentCorpusId},
    events::EventFirer, 
    executors::{Executor, HasObservers}, 
    inputs::HasTargetBytes, 
    mutators::{MutationResult, Mutator, Tokens}, 
    observers::MapObserver, 
    schedulers::TestcaseScore, 
    stages::{mutational::{MutatedTransform, MutatedTransformPost},
    MutationalStage, Restartable, RetryCountRestartHelper, Stage}, 
    state::{HasCorpus, HasCurrentTestcase, HasExecutions, HasRand, MaybeHasClientPerfMonitor}, 
    Error,
    Evaluator, 
    HasMetadata, 
    HasNamedMetadata
};
use libafl_bolts::{tuples::{Handle, Handled, MatchNameRef}, Named};

pub const STAGE_NAME: &str = "Test Stage";
pub struct TestStage<E, EM, I, S, M, F, C, Z, O>{
    name: Cow<'static, str>,
    mutator: M,
    num_tested: u32,
    observer_handle: Handle<C>,
    phantom: PhantomData<(E, EM, I, S, F, Z, O)>
}

impl<E, EM, I, S, M, F, C, Z, O> Stage<E, EM, S, Z> for TestStage<E, EM, I, S, M, F, C, Z, O>
where
    E:  Executor<EM, I, S, Z> 
         +HasObservers,
    E::Observers: MatchNameRef,
    EM: EventFirer<I, S>,
    I:  MutatedTransform<I, S> 
         +Clone
         +From<Vec<u8>>
         +HasTargetBytes,
    S:  HasCorpus<I>
         +HasMetadata
         +MaybeHasClientPerfMonitor 
         +HasCurrentTestcase<I>
         +HasRand
         +HasExecutions
         +HasNamedMetadata
         +HasCurrentCorpusId,
    M:  Mutator<I, S>,
    F:  TestcaseScore<I, S>,
    C:  Handled + AsRef<O> + AsMut<O>,
    Z:  Evaluator<E, EM, I, S>,
    O:  MapObserver,
{

    fn perform(
            &mut self,
            fuzzer: &mut Z,
            executor: &mut E,
            state: &mut S,
            manager: &mut EM,
        ) -> Result<(), libafl::Error> {
        
        
        self.num_tested += 1;
        self.clean_tokens(state);
        let optional_input = self.current_testcase_as_input(state)?;
     
        let Some(input) = optional_input else {
            return Ok(());
        };

        let num_iterations = self.iterations(state)?;
        let mut interesting_corpora: HashSet<Option<CorpusId>> = HashSet::new();

        // mutate input if interesting add to search
        for _ in 0..num_iterations {
            let mutable = input.clone();
            let corpus_id = self.mutate_and_evaluate(mutable, fuzzer, executor, state, manager)?;

            if corpus_id.is_some() {
                interesting_corpora.insert(corpus_id);
            }   
        }
        
        // search for new tokens every 1000 executions
        if self.num_tested % 1000 == 0 {
            let token_data = state.metadata_mut::<Tokens>()?;
            for token in token_data.iter() {
                let ascii = unsafe {std::str::from_utf8_unchecked(token)};
                let byte_len = token.len();
                println!("The token has {byte_len} bytes");
                println!("The string representation of the token is: {ascii}");
                println!();
            }
            let empty: Vec<Vec<u8>> = Vec::new();
            state.add_metadata(Tokens::from(empty)); 
        }

        // go through interesting corpora look for tokens
        for id in interesting_corpora {
                self.search_tokens(&input, id, fuzzer, executor, state, manager)?;
        }

        Ok(())
    }
}

/*
=========================================================================================================
*/
impl <E, EM, I, S, M, F, C, Z, O> TestStage <E, EM, I, S, M, F, C, Z, O>
where
    E:  Executor<EM, I, S, Z> 
         +HasObservers,
    E::Observers: MatchNameRef,
    EM: EventFirer<I, S>,
    I:  MutatedTransform<I, S> 
         +Clone 
         +From<Vec<u8>>
         +HasTargetBytes,
    S:  HasCorpus<I>
         +HasMetadata
         +MaybeHasClientPerfMonitor 
         +HasCurrentTestcase<I>
         +HasRand
         +HasExecutions
         +HasNamedMetadata
         +HasCurrentCorpusId,
    M:  Mutator<I, S>,
    F:  TestcaseScore<I, S>,
    C:  Handled + AsRef<O> + AsMut<O>,
    Z:  Evaluator<E, EM, I, S>,
    O:  MapObserver,
{
   
    pub  fn new(mutator: M, observer: &C) -> Self {
        Self { 
            mutator, 
            name: Cow::Owned(STAGE_NAME.to_owned()),
            num_tested: 0,
            observer_handle: observer.handle(),
            phantom: PhantomData,                
        }
    }

    pub fn search_tokens(
        &mut self,
        original: &I,
        corpus_id: Option<CorpusId>,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<(), Error>{

        // search the indices that differ
        let opt_mut = self.mutated_testcase_as_input(state, corpus_id)?;
        let Some(mutated) = opt_mut else {
            return Err(Error::empty("The mutated input could not be found"));
        };

        let input_bytes = original.target_bytes().clone();
        let diff_indices = self.search_diff_index(&original, &mutated);
        if !diff_indices.is_empty() {
            let mut seen_indices: HashSet<usize> = HashSet::new();
            for index in diff_indices {

                // only search for tokens if under threshold
                {
                    let token_data = state.metadata_mut::<Tokens>()?;

                    // early return if tokens are over threshold
                    if token_data.len() >= 100 {
                        return Ok(());
                    }
                }

                if index < 1 {
                    continue;
                }

                if seen_indices.contains(&index) {
                    continue;
                }

                // analyzing the diff itself left and right
                seen_indices.insert(index);
                let mut raw_bytes = input_bytes.to_vec();
                let changed_byte = mutated.target_bytes()[index];
                raw_bytes[index] = changed_byte;

                let mut analyze_bytes = input_bytes.to_vec();
                let mut left_index = index -1;
                let mut right_index = index + 1;


                let raw_coverage = self.get_input_coverage(
                    &raw_bytes.clone().into(), 
                    fuzzer, 
                    executor,
                    state,
                    manager
                )?;

                loop {

                    if left_index <= 0 || index - left_index + 1 >= 2 {
                        break;
                    }

                    seen_indices.insert(left_index);
                    let original_byte = analyze_bytes[left_index];
                    analyze_bytes[left_index] = changed_byte;
                    let left_coverage = self.get_input_coverage(
                        &analyze_bytes.clone().into(),
                        fuzzer,
                        executor,
                        state, 
                        manager
                    )?;

                    if raw_coverage != left_coverage {
                        break;
                    }

                    analyze_bytes[left_index] = original_byte;
                    left_index -= 1;
                }

                loop {

                    if right_index >= input_bytes.len() || right_index - index -1 >= 2{
                        break;
                    }

                    seen_indices.insert(right_index);
                    let original_byte = analyze_bytes[right_index];
                    analyze_bytes[right_index] = changed_byte;
                    let right_coverage = self.get_input_coverage(
                        &analyze_bytes.clone().into(), 
                        fuzzer, 
                        executor, 
                        state, 
                        manager
                    )?;
                                
                    if raw_coverage != right_coverage {
                        break;
                    }

                    analyze_bytes[right_index] = original_byte;
                    right_index += 1;
                }

                let token = &input_bytes.clone()[left_index..right_index].to_vec();
                let token_data = state.metadata_mut::<Tokens>()?;
                if !token_data.contains(token) {
                    token_data.add_token(token);
                }
            }
        
        }
        Ok(())
    }

    pub fn search_diff_index(&self, original: &I, mutated: &I) -> Vec<usize> {
        // find diff between original and mutated
        let mut diffs = Vec::<usize>::new();
        let origin_bytes = original.target_bytes();
        let mutated_bytes = mutated.target_bytes();
        for (i, bytes) in origin_bytes.iter().zip(mutated_bytes.iter()).enumerate() {
            let (origin, mutated) = bytes;
            if origin != mutated {
                diffs.push(i);
            }
        }
        return diffs;
    }

    pub fn clean_tokens(&self, state: &mut S) {
        let tokens_clone = state.metadata::<Tokens>().unwrap().clone();
        let mut unique: Vec<Vec<u8>> = Vec::new();
        
        'outer: for token in tokens_clone.iter() {
            for other in tokens_clone.iter() {
                if token == other {
                    continue;
                }

                // Only discard `token` if it is shorter and fully inside `other`
                if token.len() < other.len() &&
                    other.windows(token.len()).any(|w| w == token) {
                    continue 'outer; // discard token
                }
            }

            unique.push(token.clone());
        }

        state.add_metadata(Tokens::from(unique.into_boxed_slice()));
    }
    

    fn current_testcase_as_input(&self, state: &mut S) -> Result<Option<I>, Error> {
        // transform Testcase<I> containing the input to I
        let mut testcase = state.current_testcase_mut()?;
        let Ok(input) = I::try_transform_from(&mut testcase, state) else {
            return Ok(None);
        };
        drop(testcase);
        Ok(Some(input))
    }

    fn mutated_testcase_as_input(
        &self, 
        state: &mut S, 
        corpus_id: Option<CorpusId>
    ) -> Result<Option<I>, Error> {
        
        let Some(id) = corpus_id else {
            return Err(Error::empty("The corpus id is empty"));
        };
        
        let mut mutated_testcase = state.corpus().get(id)?.borrow_mut();
        let Ok(mutated) = I::try_transform_from(&mut mutated_testcase, state) else {
            return Ok(None);
        };

        Ok(Some(mutated))
    }

    fn mutate_and_evaluate(
        &mut self, 
        input: I, 
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<Option<CorpusId>, Error>{
        
        // make the input mutable and mutate
        let mut mutable_input = input.clone();
        let mutation_result = self.mutator_mut().mutate(state, &mut mutable_input)?;

        if mutation_result == MutationResult::Skipped {
            return Ok(None);
        }

        // fuzzer runs with immutable data transform back
        let (untransfomred, post) = mutable_input.try_transform_into(state)?;

        // check if mutated input is interesting
        let evaluation = fuzzer.evaluate_filtered(state, executor, manager, &untransfomred)?;
        let (exec_result, corpus_id) = evaluation;
    

        if exec_result.is_solution() {
            println!("Found new solution persisting on disk");
        }

        // check for post process in the fuzzer
        self.mutator_mut().post_exec(state, corpus_id)?;
        post.post_exec(state, corpus_id)?;

        Ok(corpus_id)
    }

    fn get_input_coverage(
        &mut self,
        input: &I, 
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
    ) -> Result<Vec<O::Entry>, Error>{

        // enclose the reset in own scope for borrow checking
        {
            let mut observers = executor.observers_mut();
            let edge_observer = observers
                .get_mut(&self.observer_handle)
                .ok_or_else(|| Error::key_not_found("invariant: MapObserver not found".to_string()))?
                .as_mut();

            // reset to analyze trace between inputs
            edge_observer.reset_map()?;
        }
        
        // feedbacks not need analyzing traces
        let (_, _) = fuzzer.evaluate_filtered(state, executor, manager, input)?;
        let coverage_map: Vec<_>;
        {   
            let mut observers = executor.observers_mut();
            let edge_observer = observers
                .get_mut(&self.observer_handle)
                .ok_or_else(|| Error::key_not_found("invariant: MapObserver not found".to_string()))?
                .as_mut();

            coverage_map = edge_observer.to_vec().clone();
        }

        Ok(coverage_map)
    }
 
}

/*
=========================================================================================================
*/
impl<E, EM, I, S, M, F, C, Z, O> Restartable<S> for TestStage<E, EM, I, S, M, F, C, Z, O>
where
    S: HasMetadata + HasNamedMetadata + HasCurrentCorpusId,
{
    fn should_restart(&mut self, state: &mut S) -> Result<bool, libafl::Error> {
        // Make sure we don't get stuck crashing on a single testcase
        RetryCountRestartHelper::should_restart(state, &self.name, 3)
    }

    fn clear_progress(&mut self, state: &mut S) -> Result<(), libafl::Error> {
        RetryCountRestartHelper::clear_progress(state, &self.name)
    }
}

impl <E, EM, I, S, M, F, C, Z, O> MutationalStage<S> for TestStage<E, EM, I, S, M, F, C, Z, O> 
where
    S: HasCurrentTestcase<I>,
    F: TestcaseScore<I, S>
{
    type Mutator = M;

    fn mutator(&self) -> &Self::Mutator {
        &self.mutator
    }

    fn mutator_mut(&mut self) -> &mut Self::Mutator {
        &mut self.mutator
    }

    fn iterations(&self, state: &mut S) -> Result<usize, Error> {
        // Update handicap
        let mut testcase = state.current_testcase_mut()?;
        let score = F::compute(state, &mut testcase)? as usize;

        Ok(score)
    }
}

impl<E, EM, I, S, M, F, C, Z, O> Named for TestStage<E, EM, I, S, M, F, C, Z, O> {
    fn name(&self) -> &Cow<'static, str> {
        &self.name
    }
}