#include <stdio.h>
#include "jpeglib.h"
#include <setjmp.h>
#include <stdint.h>

struct my_error_mgr {
  struct jpeg_error_mgr pub; /* "public" fields */
  jmp_buf setjmp_buffer;     /* for return to caller */
};
typedef struct my_error_mgr *my_error_ptr;

METHODDEF(void)
my_error_exit(j_common_ptr cinfo) {
  my_error_ptr myerr = (my_error_ptr)cinfo->err;
  // Silence error output, no printing here
  longjmp(myerr->setjmp_buffer, 1);
}

METHODDEF(void) my_output_message(j_common_ptr cinfo) {
  // Silence warning/info messages, do nothing
}

int do_read_JPEG_file(struct jpeg_decompress_struct *cinfo,
                      const uint8_t *input, size_t len) {
  struct my_error_mgr jerr;

  // Setup custom error handlers once here:
  cinfo->err = jpeg_std_error(&jerr.pub);
  jerr.pub.error_exit = my_error_exit;
  jerr.pub.output_message = my_output_message;

  if (setjmp(jerr.setjmp_buffer)) {
    return 0;
  }

  jpeg_create_decompress(cinfo);
  jpeg_mem_src(cinfo, input, len);
  (void)jpeg_read_header(cinfo, TRUE);

  (void)jpeg_start_decompress(cinfo);
  int row_stride = cinfo->output_width * cinfo->output_components;

  JSAMPARRAY buffer = (*cinfo->mem->alloc_sarray)(
      (j_common_ptr)cinfo, JPOOL_IMAGE, row_stride, 1);

  while (cinfo->output_scanline < cinfo->output_height) {
    (void)jpeg_read_scanlines(cinfo, buffer, 1);
  }

  (void)jpeg_finish_decompress(cinfo);
  jpeg_destroy_decompress(cinfo);  // cleanup!

  return 1;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct jpeg_decompress_struct cinfo;
  do_read_JPEG_file(&cinfo, data, size);
  return 0;
}