#include "vd.h"
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>
#include "partclone.h"
#include <qemu/osdep.h>
#include <getopt.h>

#include <qemu-version.h>
#include <qapi/error.h>
#include <qapi/qapi-visit-block-core.h>
#include <qapi/qobject-output-visitor.h>
#include <qapi/qmp/qjson.h>
#include <qapi/qmp/qdict.h>
#include <qapi/qmp/qstring.h>
#include <qemu/cutils.h>
#include <qemu/config-file.h>
#include <qemu/option.h>
#include <qemu/error-report.h>
#include <qemu/log.h>
#include <qom/object_interfaces.h>
#include <sysemu/sysemu.h>
#include <sysemu/block-backend.h>
#include <block/block_int.h>
#include <block/blockjob.h>
#include <block/qapi.h>
#include <crypto/init.h>
#include <trace/control.h>
#include <libfdisk/libfdisk.h>
#include <assert.h>
#include <inttypes.h>

struct virtual_disk {
    int64_t offset;
    int debug;
    char *fmt;
    BlockBackend *blk;
};
static QemuOptsList qemu_object_opts = {
    .name = "object",
    .implied_opt_name = "qom-type",
    .head = QTAILQ_HEAD_INITIALIZER(qemu_object_opts.head),
    .desc = {
        { }
    },
};

static QemuOptsList qemu_source_opts = {
    .name = "source",
    .implied_opt_name = "file",
    .head = QTAILQ_HEAD_INITIALIZER(qemu_source_opts.head),
    .desc = {
        { }
    },
};


static BlockBackend *img_open_opts(const char *optstr,
                                   QemuOpts *opts, int flags, bool writethrough,
                                   bool quiet, bool force_share)
{
    QDict *options;
    Error *local_err = NULL;
    BlockBackend *blk;
    options = qemu_opts_to_qdict(opts, NULL);
    if (force_share) {
        if (qdict_haskey(options, BDRV_OPT_FORCE_SHARE)
            && strcmp(qdict_get_str(options, BDRV_OPT_FORCE_SHARE), "on")) {
            error_report("--force-share/-U conflicts with image options");
            qobject_unref(options);
            return NULL;
        }
        qdict_put_str(options, BDRV_OPT_FORCE_SHARE, "on");
    }
    blk = blk_new_open(NULL, NULL, options, flags, &local_err);
    if (!blk) {
        error_reportf_err(local_err, "Could not open '%s': ", optstr);
        return NULL;
    }
    blk_set_enable_write_cache(blk, !writethrough);

    return blk;
}

static BlockBackend *img_open_file(const char *filename,
                                   QDict *options,
                                   const char *fmt, int flags,
                                   bool writethrough, bool quiet,
                                   bool force_share)
{
    BlockBackend *blk;
    Error *local_err = NULL;

    if (!options) {
        options = qdict_new();
    }
    if (fmt) {
        qdict_put_str(options, "driver", fmt);
    }

    if (force_share) {
        qdict_put_bool(options, BDRV_OPT_FORCE_SHARE, true);
    }
    blk = blk_new_open(filename, NULL, options, flags, &local_err);
    if (!blk) {
        error_reportf_err(local_err, "Could not open '%s': ", filename);
        return NULL;
    }
    blk_set_enable_write_cache(blk, !writethrough);

    return blk;
}

static BlockBackend *img_open(bool image_opts,
                              const char *filename,
                              const char *fmt, int flags, bool writethrough,
                              bool quiet, bool force_share)
{
    BlockBackend *blk;
    if (image_opts) {
        QemuOpts *opts;
        if (fmt) {
            error_report("--image-opts and --format are mutually exclusive");
            return NULL;
        }
        opts = qemu_opts_parse_noisily(qemu_find_opts("source"),
                                       filename, true);
        if (!opts) {
            return NULL;
        }
        blk = img_open_opts(filename, opts, flags, writethrough, quiet,
                            force_share);
    } else {
        blk = img_open_file(filename, NULL, fmt, flags, writethrough, quiet,
                            force_share);
    }
    return blk;
}

int libvd_init(int argc, char **argv) 
{
    Error *local_error = NULL;
    int c;
    int err = 0;

    static const struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
        {"source", required_argument, NULL, 's'},
        {"image", required_argument, NULL, 'i'},
        {"object", required_argument, NULL, 'o'},
        {"format", required_argument, NULL, 'f'},
        {0, 0, 0, 0}
    };

#ifdef CONFIG_POSIX
    signal(SIGPIPE, SIG_IGN);
#endif

    module_call_init(MODULE_INIT_TRACE);
    error_set_progname(argv[0]);
    qemu_init_exec_dir(argv[0]);

    if (qemu_init_main_loop(&local_error)) {
        error_report_err(local_error);
        return -1;
    }

    qcrypto_init(&error_fatal);

    module_call_init(MODULE_INIT_QOM);
    bdrv_init();

    qemu_add_opts(&qemu_object_opts);
    qemu_add_opts(&qemu_source_opts);
    qemu_add_opts(&qemu_trace_opts);

	return 0;
}

void libvd_destroy()
{

}

#ifndef p2d_offset
#define p2d_offset(vd, poffset) ((vd)->offset + (poffset))  
#endif

virtual_disk_t vd_open(const char *file, const char *fmt, const int64_t offset, const int debug)
{

    int flags = BDRV_O_RDWR;
    bool quiet = false;
    bool tgt_image_opts = false;
    bool writethrough = true;
    
    virtual_disk_t vd = malloc(sizeof (struct virtual_disk));
    if (vd == NULL) {
        return vd;
    }
    
    memset(vd, 0, sizeof(struct virtual_disk));

    vd->offset = offset;
    vd->debug = debug;
    vd->fmt = strdup(fmt);


    vd->blk = img_open(tgt_image_opts, file, fmt,
                            flags, writethrough, quiet, false);


	log_mesg(0, 0, 1, debug, "open virtual disk. disk=%s, fmt=%s, offset=%lld, vd=%p\n", file, fmt, offset, vd);
    return vd;
}

void vd_close(const virtual_disk_t vd) {
    
    assert(vd != NULL);

    if (vd->blk) {
        blk_flush(vd->blk);
        blk_unref(vd->blk);
    }

	log_mesg(0, 0, 1, vd->debug, "close virtual disk. vd=%p\n", vd);
    if (vd->fmt) {
        free(vd->fmt);
    }
    free(vd);
}

int vd_write(const virtual_disk_t vd, const int64_t offset, const void *buf, const int size) {

    int64_t doffset = p2d_offset(vd, offset);

    int nwrite = blk_pwrite(vd->blk, doffset, buf, size, 0);
	log_mesg(0, 0, 1, vd->debug, "write virtual disk. vd=%p, fmt=%s, base=%lld, offset=%lld, doffset=%lld data=%p, write=%lld, written=%lld\n", vd, vd->fmt, vd->offset, doffset, offset, buf, size, nwrite);
    return nwrite;
}

int vd_read(const virtual_disk_t vd, const int64_t offset, void *buf, int max) {
    int nread = blk_pread(vd->blk, offset, buf, max);
	log_mesg(0, 0, 1, vd->debug, "read virtual disk. vd=%p, fmt=%s, base=%lld, offset=%lld, data=%p, size=%lld\n", vd, vd->fmt, vd->offset, offset, buf, max);
    return nread;
}

void vd_sync(const virtual_disk_t vd) {

    assert(vd != NULL);

	log_mesg(0, 0, 1, vd->debug, "sync virtual disk. vd=%p, fmt=%s, base=%lld\n", vd, vd->fmt, vd->offset);
}
