/*
 * QEMU Block driver for OpenvStorage
 *
 * Copyright (C) 2015-2016 iNuron NV
 *
 * Authors:
 *  Chrysostomos Nanakos (cnanakos@openvstorage.com)
 *
 * This file is part of Open vStorage Open Source Edition (OSE),
 * as available from
 *
 *      http://www.openvstorage.org and
 *      http://www.openvstorage.com.
 *
 * This file is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License v3 (GNU AGPLv3)
 * as published by the Free Software Foundation, in version 3 as it comes in
 * the LICENSE.txt file of the Open vStorage OSE distribution.
 * Open vStorage is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY of any kind.
 *
 */

/*
 * VM Image on OpenvStorage volume is specified like this:
 *
 * file.transport=[shm|tcp|rdma],file.driver=openvstorage,
 * file.volume=<volume_name>,[file.host=server,file.port=port],
 * [file.snapshot-timeout=120]
 *
 * or
 *
 * file=openvstorage:<volume_name>
 * file=openvstorage:<volume_name>[:snapshot-timeout=<timeout>]
 *
 * or
 *
 * file=openvstorage[+transport]:[server[:port]/volume_name]:
 * [snapshot-timeout=<timeout>]
 *
 * 'openvstorage' is the protocol.
 *
 * 'transport' is the transport type used to connect to OpenvStorage.
 * Valid transport types are shm, tcp and rdma. If a transport type isn't
 * specified then shm is assumed.
 *
 * 'server' specifies the server where the volume resides. This can be either
 * hostname or ipv4 address. If transport type is shm, then 'server' field
 * should not be specified.
 *
 * 'port' is the port number on which OpenvStorage network interface is
 * listening. This is optional and if not specified QEMU will use the default
 * port. If the transport type is shm, then 'port' should not be specified.
 *
 * 'volume_name' is the name of the OpenvStorage volume.
 *
 * 'snapshot-timeout' is the timeout for the volume snapshot to be synced on
 * the backend. If the timeout expires then the snapshot operation will fail.
 *
 * Examples:
 *
 * file.driver=openvstorage,file.volume=my_vm_volume
 * file.driver=openvstorage,file.volume=my_vm_volume, \
 * file.snapshot-timeout=120
 *
 * or
 *
 * file=openvstorage:my_vm_volume
 * file=openvstorage:my_vm_volume:snapshot-timeout=120
 *
 * or
 *
 * file=openvstorage+tcp:1.2.3.4:21321/my_volume,snapshot-timeout=120
 *
 * or
 *
 * file.driver=openvstorage,file.transport=rdma,file.volume=my_vm_volume,
 * file.snapshot-timeout=120,file.host=1.2.3.4,file.port=21321
 *
 */
#include <openvstorage/volumedriver.h>
#include "block/block_int.h"
#include "qapi/qmp/qint.h"
#include "qapi/qmp/qstring.h"
#include "qapi/qmp/qjson.h"
#include "qemu/error-report.h"
#include "qemu/atomic.h"
#include "qemu/uri.h"

#define MAX_REQUEST_SIZE        32768
#define OVS_MAX_SNAPS           100
#define OVS_DFL_SNAP_TIMEOUT    120
#define OVS_DFL_PORT            21321
/* options related */
#define OVS_OPT_TRANSPORT       "transport"
#define OVS_OPT_HOST            "host"
#define OVS_OPT_PORT            "port"
#define OVS_OPT_VOLUME          "volume"
#define OVS_OPT_SNAP_TIMEOUT    "snapshot-timeout"

typedef enum {
    OVS_OP_READ,
    OVS_OP_WRITE,
    OVS_OP_FLUSH,
} OpenvStorageCmd;

typedef struct OpenvStorageAIOCB {
    BlockAIOCB common;
    QEMUBH *bh;
    struct BDRVOpenvStorageState *s;
    QEMUIOVector *qiov;
    OpenvStorageCmd cmd;
    uint64_t size;
    ssize_t ret;
} OpenvStorageAIOCB;

typedef struct BDRVOpenvStorageState {
    OpenvStorageAIOCB *event_acb;
    ovs_ctx_t *ctx;
    char *volume_name;
    int snapshot_timeout;
    bool is_network;
} BDRVOpenvStorageState;

typedef struct OpenvStorageAIOSegregatedReq
{
    uint64_t count;
    uint64_t total;
    int ref;
    bool one_or_many_failed_after;
    bool failed;
} OpenvStorageAIOSegregatedReq;

typedef struct OpenvStorageAIORequest {
    struct ovs_aiocb *aiocbp;
    ovs_buffer_t *ovs_buffer;
    OpenvStorageAIOCB *aio_cb;
    ssize_t ret;
    uint64_t pos;
    OpenvStorageAIOSegregatedReq *seg_request;
} OpenvStorageAIORequest;

static void qemu_openvstorage_complete_aio(void *opaque);

static void openvstorage_finish_aiocb(ovs_completion_t *completion, void *arg)
{
    OpenvStorageAIORequest *aio_request = (OpenvStorageAIORequest*) arg;
    OpenvStorageAIOCB *aio_cb = aio_request->aio_cb;
    OpenvStorageAIOSegregatedReq *f = aio_request->seg_request;
    struct ovs_aiocb *aiocbp = aio_request->aiocbp;

    if (aio_cb->cmd != OVS_OP_FLUSH)
    {
        aio_request->ret = ovs_aio_return(aio_cb->s->ctx, aiocbp);
        ovs_aio_finish(aio_cb->s->ctx, aiocbp);
    }
    else
    {
        aio_request->ret = ovs_aio_return_completion(completion);
    }
    ovs_aio_release_completion(completion);

    if (aio_request->ret == -1)
    {
        f->one_or_many_failed_after = true;
    }

    if (aio_cb->cmd == OVS_OP_READ && aio_request->ret != -1)
    {
        qemu_iovec_from_buf(aio_cb->qiov,
                            aio_request->pos,
                            aiocbp->aio_buf,
                            aio_request->ret);
    }

    if (aio_cb->cmd != OVS_OP_FLUSH)
    {
        ovs_deallocate(aio_cb->s->ctx,
                       aio_request->ovs_buffer);
    }

    if (aio_request->ret > 0)
    {
        atomic_add(&f->count, aio_request->ret);
    }
    if (atomic_fetch_dec(&f->ref) == 1)
    {
        if (!f->failed)
        {
            if (f->one_or_many_failed_after)
            {
                aio_cb->ret = -EIO;
            }
            else
            {
                aio_cb->ret = f->count;
                if ((aio_cb->ret < f->total) && (aio_cb->cmd == OVS_OP_READ))
                {
                    memset(aio_cb->qiov + aio_cb->ret, 0,
                           f->total - aio_cb->ret);
                }
                else if (aio_cb->ret != f->total)
                {
                    aio_cb->ret = -EIO;
                }
                else
                {
                    aio_cb->ret = 0;
                }
            }
            aio_cb->bh = aio_bh_new(
                    bdrv_get_aio_context(aio_cb->common.bs),
                    qemu_openvstorage_complete_aio, aio_request);
            qemu_bh_schedule(aio_cb->bh);
        }
        else
        {
            g_free(aiocbp);
            g_free(aio_request);
        }
        g_free(f);
    }
    else
    {
        g_free(aiocbp);
        g_free(aio_request);
    }
}

static void qemu_openvstorage_complete_aio(void *opaque)
{
    OpenvStorageAIORequest *aio_request = (OpenvStorageAIORequest*) opaque;
    OpenvStorageAIOCB *aio_cb = aio_request->aio_cb;
    struct ovs_aiocb *aiocbp = aio_request->aiocbp;

    qemu_bh_delete(aio_cb->bh);
    aio_cb->common.cb(aio_cb->common.opaque, aio_cb->ret);

    qemu_aio_unref(aio_cb);
    g_free(aiocbp);
    g_free(aio_request);
}

static QemuOptsList openvstorage_runtime_opts = {
    .name = "openvstorage",
    .head = QTAILQ_HEAD_INITIALIZER(openvstorage_runtime_opts.head),
    .desc = {
        {
            .name = OVS_OPT_TRANSPORT,
            .type = QEMU_OPT_STRING,
            .help = "Transport type (shm/tcp/rdma)",
        },
        {
            .name = OVS_OPT_HOST,
            .type = QEMU_OPT_STRING,
            .help = "Host address/name",
        },
        {
            .name = OVS_OPT_PORT,
            .type = QEMU_OPT_NUMBER,
            .help = "Host port",
        },
        {
            .name = OVS_OPT_VOLUME,
            .type = QEMU_OPT_STRING,
            .help = "Name of the volume image",
        },
        {
            .name = OVS_OPT_SNAP_TIMEOUT,
            .type = QEMU_OPT_NUMBER,
            .help = "Timeout for the snapshot to be synced on the backend",
        },
        {/* end of list */}
    },
};

static void
openvstorage_parse_filename_opts(char *path,
                                 Error **errp,
                                 char **host,
                                 gpointer *port,
                                 char **volume,
                                 gpointer *snapshot_timeout,
                                 bool is_network)
{
    const char *a;
    char *endptr, *inetaddr;
    char *tokens[3], *ptoken;
    int timeout;

    if (!path) {
        error_setg(errp, "invalid argument");
        return;
    }

    if (is_network) {
        tokens[0] = strsep(&path, "/");
        tokens[1] = strsep(&path, ":");
        tokens[2] = strsep(&path, "\0");
    } else {
        tokens[0] = strsep(&path, ":");
        tokens[1] = strsep(&path, "\0");
    }

    if (is_network && ((tokens[0] && !strlen(tokens[0])) ||
                       (tokens[1] && !strlen(tokens[1])))) {
        error_setg(errp, "server and volume name must be specified");
        return;
    } else if (!is_network && tokens[0] && !strlen(tokens[0])) {
        error_setg(errp, "volume name must be specified");
        return;
    }

    *volume = is_network ? g_strdup(tokens[1]) : g_strdup(tokens[0]);
    if (is_network) {
        if (!index(tokens[0], ':')) {
            *port = GINT_TO_POINTER(OVS_DFL_PORT);
            *host = g_strdup(tokens[0]);
        } else {
            inetaddr = g_strdup(tokens[0]);
            *host = g_strdup(strtok(inetaddr, ":"));
            ptoken = strtok(NULL, "\0");
            if (ptoken != NULL) {
                int p = strtoul(ptoken, &endptr, 10);
                if (strlen(endptr)) {
                    error_setg(errp, "server/port must be specified");
                    g_free(inetaddr);
                    return;
                }
                *port = GINT_TO_POINTER(p);
            } else {
                error_setg(errp, "server/port must be specified");
                g_free(inetaddr);
                return;
            }
            g_free(inetaddr);
        }
    }

    char *t = is_network ? tokens[2] : tokens[1];
    if (t != NULL && strstart(t, OVS_OPT_SNAP_TIMEOUT"=", &a)) {
        if (strlen(a) > 0) {
            timeout = strtoul(a, &endptr, 10);
            if (strlen(endptr)) {
                return;
            }
            *snapshot_timeout = GINT_TO_POINTER(timeout);
        }
    }
}

static int qemu_openvstorage_uri_parse(const URI* uri,
                                       char **transport,
                                       bool *is_network,
                                       Error **errp)
{
    if (!uri->scheme || !strcmp(uri->scheme, "openvstorage")) {
        *transport = g_strdup("shm");
        *is_network = false;
    } else if (!strcmp(uri->scheme, "openvstorage+tcp")) {
        *transport = g_strdup("tcp");
    } else if (!strcmp(uri->scheme, "openvstorage+rdma")) {
        *transport = g_strdup("rdma");
    } else {
        return -EINVAL;
    }

    if (!uri->path || !strlen(uri->path)) {
        if (*is_network) {
            error_setg(errp, "hostname must be specified first");
        } else {
            error_setg(errp, "volume name must be specified first");
        }
        return -EINVAL;
    }
    return 0;
}

static void qemu_openvstorage_parse_filename(const char *filename,
                                             QDict *options,
                                             Error **errp)
{
    URI *uri;
    bool is_network = true;
    char *transport = NULL;
    char *volume = NULL;
    char *host = NULL;
    gpointer snapshot_timeout = NULL;
    gpointer port = NULL;

    if (qdict_haskey(options, OVS_OPT_VOLUME) ||
        qdict_haskey(options, OVS_OPT_SNAP_TIMEOUT) ||
        qdict_haskey(options, OVS_OPT_HOST) ||
        qdict_haskey(options, OVS_OPT_PORT) ||
        qdict_haskey(options, OVS_OPT_TRANSPORT)) {
        error_setg(errp, "volume/stimeout/server/port/transport and a filename"
                         "may not be specified at the same time");
        return;
    }

    uri = uri_parse(filename);
    if (!uri) {
        return;
    }

    int ret = qemu_openvstorage_uri_parse(uri, &transport, &is_network, errp);
    if (ret < 0) {
        uri_free(uri);
        goto exit;
    }

    openvstorage_parse_filename_opts(uri->path,
                                     errp,
                                     &host,
                                     &port,
                                     &volume,
                                     &snapshot_timeout,
                                     is_network);
    uri_free(uri);

    qdict_put(options,
              OVS_OPT_TRANSPORT,
              qstring_from_str(transport));

    if (is_network && (!host || !port || !volume)) {
        goto exit;
    } else if (!is_network && !volume) {
        goto exit;
    }

    if (host) {
        qdict_put(options,
                  OVS_OPT_HOST,
                  qstring_from_str(host));
    }

    if (port) {
        qdict_put(options,
                  OVS_OPT_PORT,
                  qint_from_int(GPOINTER_TO_INT(port)));
    }

    if (volume) {
        qdict_put(options,
                  OVS_OPT_VOLUME,
                  qstring_from_str(volume));
    }

    if (snapshot_timeout) {
        qdict_put(options,
                  OVS_OPT_SNAP_TIMEOUT,
                  qint_from_int(GPOINTER_TO_INT(snapshot_timeout)));
    }
exit:
    g_free(transport);
    g_free(host);
    g_free(volume);
    return;
}

static void
qemu_openvstorage_parse_flags(int bdrv_flags, int *open_flags)
{
    assert(open_flags != NULL);

    if (bdrv_flags & BDRV_O_RDWR) {
        *open_flags |= O_RDWR;
    } else {
        *open_flags |= O_RDONLY;
    }
}

static int
qemu_openvstorage_open(BlockDriverState *bs,
                       QDict *options,
                       int bdrv_flags,
                       Error **errp)
{
    int ret = 0;
    int open_flags = 0;
    QemuOpts *opts;
    Error *local_err = NULL;
    const char *transport;
    const char *host;
    int port;
    const char *volume_name;
    BDRVOpenvStorageState *s = bs->opaque;

    opts = qemu_opts_create(&openvstorage_runtime_opts, NULL, 0, &error_abort);
    qemu_opts_absorb_qdict(opts, options, &local_err);

    if (local_err) {
        error_propagate(errp, local_err);
        ret = -EINVAL;
        goto err_exit;
    }

    transport = qemu_opt_get(opts, OVS_OPT_TRANSPORT);
    if (!strcmp(transport, "shm")) {
        s->is_network = false;
    } else {
        s->is_network = true;
    }

    host = qemu_opt_get(opts, OVS_OPT_HOST);
    port = qemu_opt_get_number(opts,
                               OVS_OPT_PORT,
                               OVS_DFL_PORT);
    volume_name = qemu_opt_get(opts, OVS_OPT_VOLUME);

    ovs_ctx_attr_t *ctx_attr = ovs_ctx_attr_new();
    assert(ctx_attr != NULL);

    if (ovs_ctx_attr_set_transport(ctx_attr,
                                   transport,
                                   host,
                                   port) < 0) {
        ret = -errno;
        error_setg(errp, "cannot set transport type: %s", strerror(errno));
        ovs_ctx_attr_destroy(ctx_attr);
        goto err_exit;
    }

    s->ctx = ovs_ctx_new(ctx_attr);
    ovs_ctx_attr_destroy(ctx_attr);
    if (s->ctx == NULL) {
        ret = -errno;
        error_setg(errp, "cannot create context: %s", strerror(errno));
        goto err_exit;
    }
    qemu_openvstorage_parse_flags(bdrv_flags, &open_flags);

    ret = ovs_ctx_init(s->ctx, volume_name, open_flags);
    if (ret < 0) {
        ret = -errno;
        error_setg(errp, "cannot open volume: %s", strerror(errno));
        ovs_ctx_destroy(s->ctx);
        goto err_exit;
    } else {
        s->volume_name = g_strdup(volume_name);
        s->snapshot_timeout = qemu_opt_get_number(opts,
                                                  OVS_OPT_SNAP_TIMEOUT,
                                                  OVS_DFL_SNAP_TIMEOUT);
    }
    qemu_opts_del(opts);
    return 0;
err_exit:
    g_free(s->volume_name);
    qemu_opts_del(opts);
    return ret;
}

static void
qemu_openvstorage_close(BlockDriverState *bs)
{
    BDRVOpenvStorageState *s = bs->opaque;
    assert(s->ctx);
    g_free(s->volume_name);
    ovs_ctx_destroy(s->ctx);
}

static int64_t
qemu_openvstorage_getlength(BlockDriverState *bs)
{
    BDRVOpenvStorageState *s = bs->opaque;
    assert(s->ctx);
    struct stat st;
    int ret = ovs_stat(s->ctx, &st);
    if (ret < 0) {
        return ret;
    }
    return st.st_size;
}

static QemuOptsList openvstorage_create_opts = {
    .name = "openvstorage-create-opts",
    .head = QTAILQ_HEAD_INITIALIZER(openvstorage_create_opts.head),
    .desc = {
        {
            .name = BLOCK_OPT_SIZE,
            .type = QEMU_OPT_SIZE,
            .help = "Virtual disk size"
        },
        {/* end if list */}
    }
};

static int
qemu_openvstorage_create(const char* filename,
                         QemuOpts *opts,
                         Error **errp)
{
    int ret;
    URI *uri;
    bool is_network = true;
    char *transport = NULL;
    char *host = NULL;
    char *volume_name = NULL;
    gpointer stimeout = NULL;
    gpointer port = NULL;
    uint64_t size = 0;

    uri = uri_parse(filename);
    if (!uri) {
        return -EINVAL;
    }

    ret = qemu_openvstorage_uri_parse(uri, &transport, &is_network, errp);
    if (ret < 0) {
        uri_free(uri);
        goto uri_exit;
    }
    openvstorage_parse_filename_opts(uri->path,
                                     errp,
                                     &host,
                                     &port,
                                     &volume_name,
                                     &stimeout,
                                     is_network);
    uri_free(uri);

    if (is_network && (!host || !port || !volume_name)) {
        ret = -EINVAL;
        goto err_exit;
    } else if (!is_network && !volume_name) {
        ret = -EINVAL;
        goto err_exit;
    }

    size = ROUND_UP(qemu_opt_get_size_del(opts, BLOCK_OPT_SIZE, 0),
                    BDRV_SECTOR_SIZE);

    ovs_ctx_attr_t *ctx_attr = ovs_ctx_attr_new();
    assert(ctx_attr != NULL);

    ret = ovs_ctx_attr_set_transport(ctx_attr,
                                     transport,
                                     host,
                                     GPOINTER_TO_INT(port));
    if (ret < 0) {
        error_setg(errp, "cannot set transport type: %s ", strerror(errno));
        ret = -errno;
        goto attr_exit;
    }

    ovs_ctx_t *ctx = ovs_ctx_new(ctx_attr);
    assert(ctx != NULL);

    if (size > 0 && volume_name != NULL) {
        ret = ovs_create_volume(ctx, volume_name, size);
        if (ret < 0) {
            error_setg(errp, "cannot create volume: %s ", strerror(errno));
            ret = -errno;
        }
    } else {
        ret = -EINVAL;
    }
    ovs_ctx_destroy(ctx);
attr_exit:
    ovs_ctx_attr_destroy(ctx_attr);
err_exit:
    g_free(host);
    g_free(volume_name);
uri_exit:
    g_free(transport);
    return ret;
}

static const AIOCBInfo openvstorage_aiocb_info = {
    .aiocb_size = sizeof(OpenvStorageAIOCB),
};

static int
qemu_openvstorage_submit_aio_request(BlockDriverState *bs,
                                     uint64_t pos,
                                     uint64_t size,
                                     off_t offset,
                                     OpenvStorageAIOCB *aio_cb,
                                     OpenvStorageAIOSegregatedReq *f,
                                     OpenvStorageCmd cmd)
{
    BDRVOpenvStorageState *s = bs->opaque;
    int ret;
    ovs_buffer_t *ovs_buf = NULL;
    void *buf = NULL;

    if (cmd != OVS_OP_FLUSH) {
        ovs_buf = ovs_allocate(s->ctx, size);
        if (ovs_buf == NULL) {
            error_report("%s: cannot allocate buffer, size: %ld",
                         __func__,
                         size);
            goto failed_on_allocation;
        }
        buf = ovs_buffer_data(ovs_buf);
    }

    if (cmd == OVS_OP_WRITE) {
        qemu_iovec_to_buf(aio_cb->qiov,
                          pos,
                          buf,
                          size);
    }

    struct ovs_aiocb *aiocbp = g_new(struct ovs_aiocb, 1);
    aiocbp->aio_buf = buf;
    aiocbp->aio_nbytes = size;
    aiocbp->aio_offset = offset;

    OpenvStorageAIORequest *aio_request = g_new(OpenvStorageAIORequest, 1);
    aio_request->aiocbp = aiocbp;
    aio_request->aio_cb = aio_cb;
    aio_request->ovs_buffer = ovs_buf;
    aio_request->pos = pos;
    aio_request->seg_request = f;

    ovs_completion_t *completion =
        ovs_aio_create_completion((ovs_callback_t) openvstorage_finish_aiocb,
                                  (void*)aio_request);

    if (completion == NULL) {
        error_report("%s: could not create completion", __func__);
        goto failed_on_completion;
    }

    switch (cmd)
    {
    case OVS_OP_WRITE:
        ret = ovs_aio_writecb(s->ctx, aiocbp, completion);
        break;
    case OVS_OP_READ:
        ret = ovs_aio_readcb(s->ctx, aiocbp, completion);
        break;
    case OVS_OP_FLUSH:
        ret = ovs_aio_flushcb(s->ctx, completion);
        break;
    default:
        ret = -EINVAL;
    }

    if (ret < 0) {
        goto err_exit;
    }

    return 0;

err_exit:
    error_report("%s: failed to submit aio request", __func__);
    ovs_aio_release_completion(completion);
failed_on_completion:
    ovs_deallocate(s->ctx, ovs_buf);
    g_free(aiocbp);
    g_free(aio_request);
failed_on_allocation:
    return -EIO;
}

static int
qemu_openvstorage_aio_segregated_rw(BlockDriverState *bs,
                                    uint64_t size,
                                    off_t offset,
                                    OpenvStorageAIOCB *aio_cb,
                                    OpenvStorageCmd cmd)
{
    int ret, requests_nr;
    uint64_t pos = 0;
    OpenvStorageAIOSegregatedReq *seg_request;

    seg_request = g_new0(OpenvStorageAIOSegregatedReq, 1);

    if (cmd == OVS_OP_FLUSH) {
        requests_nr = 1;
    } else {
        requests_nr = (int)(size / MAX_REQUEST_SIZE) + \
                      ((size % MAX_REQUEST_SIZE) ? 1 : 0);
    }
    seg_request->total = size;
    atomic_mb_set(&seg_request->ref, requests_nr);

    while (requests_nr > 1) {
        ret = qemu_openvstorage_submit_aio_request(bs,
                                                   pos,
                                                   MAX_REQUEST_SIZE,
                                                   offset + pos,
                                                   aio_cb,
                                                   seg_request,
                                                   cmd);
        if (ret < 0) {
            goto err_exit;
        }
        size -= MAX_REQUEST_SIZE;
        pos += MAX_REQUEST_SIZE;
        requests_nr--;
    }
    ret = qemu_openvstorage_submit_aio_request(bs,
                                               pos,
                                               size,
                                               offset + pos,
                                               aio_cb,
                                               seg_request,
                                               cmd);
    if (ret < 0) {
        goto err_exit;
    }
    return 0;

err_exit:
    seg_request->failed = true;
    if (atomic_fetch_sub(&seg_request->ref, requests_nr) == requests_nr) {
        g_free(seg_request);
    }
    return ret;
}

static BlockAIOCB *qemu_openvstorage_aio_rw(BlockDriverState *bs,
                                            int64_t sector_num,
                                            QEMUIOVector *qiov,
                                            int nb_sectors,
                                            BlockCompletionFunc *cb,
                                            void *opaque,
                                            OpenvStorageCmd cmd)
{
    int ret;
    int64_t size, offset;
    OpenvStorageAIOCB *aio_cb;
    BDRVOpenvStorageState *s = bs->opaque;

    aio_cb = qemu_aio_get(&openvstorage_aiocb_info, bs, cb, opaque);
    aio_cb->cmd = cmd;
    aio_cb->qiov = qiov;
    aio_cb->ret = 0;
    aio_cb->s = s;

    size = nb_sectors * BDRV_SECTOR_SIZE;
    offset = sector_num * BDRV_SECTOR_SIZE;
    aio_cb->size = size;

    ret = qemu_openvstorage_aio_segregated_rw(bs,
                                              size,
                                              offset,
                                              aio_cb,
                                              cmd);
    if (ret < 0) {
        goto err_exit;
    }
    return &aio_cb->common;

err_exit:
    error_report("%s: I/O error", __func__);
    qemu_aio_unref(aio_cb);
    return NULL;
}

static BlockAIOCB *qemu_openvstorage_aio_readv(BlockDriverState *bs,
                                               int64_t sector_num,
                                               QEMUIOVector *qiov,
                                               int nb_sectors,
                                               BlockCompletionFunc *cb,
                                               void *opaque)
{
    return qemu_openvstorage_aio_rw(bs,
                                    sector_num,
                                    qiov,
                                    nb_sectors,
                                    cb,
                                    opaque,
                                    OVS_OP_READ);
};

static BlockAIOCB *qemu_openvstorage_aio_writev(BlockDriverState *bs,
                                                int64_t sector_num,
                                                QEMUIOVector *qiov,
                                                int nb_sectors,
                                                BlockCompletionFunc *cb,
                                                void *opaque)
{
    return qemu_openvstorage_aio_rw(bs,
                                    sector_num,
                                    qiov,
                                    nb_sectors,
                                    cb,
                                    opaque,
                                    OVS_OP_WRITE);
};

static BlockAIOCB *qemu_openvstorage_aio_flush(BlockDriverState *bs,
                                               BlockCompletionFunc *cb,
                                               void *opaque)
{
    return qemu_openvstorage_aio_rw(bs,
                                    0,
                                    NULL,
                                    0,
                                    cb,
                                    opaque,
                                    OVS_OP_FLUSH);
}

static int qemu_openvstorage_snap_create(BlockDriverState *bs,
                                         QEMUSnapshotInfo *sn_info)
{
    BDRVOpenvStorageState *s = bs->opaque;
    int ret;

    if (sn_info->name[0] == '\0') {
        return -EINVAL;
    }

    if (sn_info->id_str[0] != '\0' &&
        strcmp(sn_info->id_str, sn_info->name) != 0) {
        return -EINVAL;
    }

    if (strlen(sn_info->name) >= sizeof(sn_info->id_str)) {
        return -ERANGE;
    }

    ret = ovs_snapshot_create(s->ctx,
                              s->volume_name,
                              sn_info->name,
                              s->snapshot_timeout);
    if (ret < 0) {
        ret = -errno;
        error_report("failed to create snapshot: %s", strerror(errno));
    }
    return ret;
}

static int qemu_openvstorage_snap_remove(BlockDriverState *bs,
                                         const char *snapshot_id,
                                         const char *snapshot_name,
                                         Error **errp)
{
    BDRVOpenvStorageState *s = bs->opaque;
    int ret;

    if (!snapshot_name) {
        error_setg(errp, "openvstorage needs a valid snapshot name");
        return -EINVAL;
    }

    if (snapshot_id && strcmp(snapshot_id, snapshot_name)) {
        error_setg(errp,
                   "openvstorage doesn't support snapshot id, it should be "
                   "NULL or equal to snapshot name");
        return -EINVAL;
    }

    ret = ovs_snapshot_remove(s->ctx, s->volume_name, snapshot_name);
    if (ret < 0) {
        ret = -errno;
        error_setg_errno(errp, errno, "failed to remove snapshot");
    }
    return ret;
}

static int qemu_openvstorage_snap_rollback(BlockDriverState *bs,
                                           const char *snapshot_name)
{
    BDRVOpenvStorageState *s = bs->opaque;
    int ret;

    ret = ovs_snapshot_rollback(s->ctx, s->volume_name, snapshot_name);
    if (ret < 0) {
        ret = -errno;
    }
    return ret;
}

static int qemu_openvstorage_snap_list(BlockDriverState *bs,
                                       QEMUSnapshotInfo **psn_tab)
{
    BDRVOpenvStorageState *s = bs->opaque;
    QEMUSnapshotInfo *sn_info, *sn_tab = NULL;
    int i, snap_count;
    ovs_snapshot_info_t *snaps;
    int max_snaps = OVS_MAX_SNAPS;

    do {
        snaps = g_new(ovs_snapshot_info_t, max_snaps);
        snap_count = ovs_snapshot_list(s->ctx,
                                       s->volume_name,
                                       snaps,
                                       &max_snaps);
        if (snap_count <= 0) {
            g_free(snaps);
        }
    } while (snap_count == -1 && errno == ERANGE);

    if (snap_count <= 0) {
        snap_count = -errno;
        goto done;
    }

    sn_tab = g_new0(QEMUSnapshotInfo, snap_count);

    for (i = 0; i < snap_count; i++) {
        const char *snap_name = snaps[i].name;

        sn_info = sn_tab + i;
        pstrcpy(sn_info->id_str, sizeof(sn_info->id_str), snap_name);
        pstrcpy(sn_info->name, sizeof(sn_info->name), snap_name);

        sn_info->vm_state_size = snaps[i].size;
        sn_info->date_sec = 0;
        sn_info->date_nsec = 0;
        sn_info->vm_clock_nsec = 0;
    }
    ovs_snapshot_list_free(snaps);
    g_free(snaps);
done:
    *psn_tab = sn_tab;
    return snap_count;
}

static BlockDriver bdrv_openvstorage_shm = {
    .format_name          = "openvstorage",
    .protocol_name        = "openvstorage",
    .instance_size        = sizeof(BDRVOpenvStorageState),
    .bdrv_parse_filename  = qemu_openvstorage_parse_filename,

    .bdrv_file_open       = qemu_openvstorage_open,
    .bdrv_close           = qemu_openvstorage_close,
    .bdrv_getlength       = qemu_openvstorage_getlength,
    .bdrv_aio_readv       = qemu_openvstorage_aio_readv,
    .bdrv_aio_writev      = qemu_openvstorage_aio_writev,
    .bdrv_aio_flush       = qemu_openvstorage_aio_flush,
    .bdrv_has_zero_init   = bdrv_has_zero_init_1,

    .bdrv_snapshot_create = qemu_openvstorage_snap_create,
    .bdrv_snapshot_delete = qemu_openvstorage_snap_remove,
    .bdrv_snapshot_list   = qemu_openvstorage_snap_list,
    .bdrv_snapshot_goto   = qemu_openvstorage_snap_rollback,

    .bdrv_create          = qemu_openvstorage_create,
    .create_opts          = &openvstorage_create_opts,
};

static BlockDriver bdrv_openvstorage_tcp = {
    .format_name          = "openvstorage",
    .protocol_name        = "openvstorage+tcp",
    .instance_size        = sizeof(BDRVOpenvStorageState),
    .bdrv_parse_filename  = qemu_openvstorage_parse_filename,

    .bdrv_file_open       = qemu_openvstorage_open,
    .bdrv_close           = qemu_openvstorage_close,
    .bdrv_getlength       = qemu_openvstorage_getlength,
    .bdrv_aio_readv       = qemu_openvstorage_aio_readv,
    .bdrv_aio_writev      = qemu_openvstorage_aio_writev,
    .bdrv_aio_flush       = qemu_openvstorage_aio_flush,
    .bdrv_has_zero_init   = bdrv_has_zero_init_1,

    .bdrv_snapshot_create = qemu_openvstorage_snap_create,
    .bdrv_snapshot_delete = qemu_openvstorage_snap_remove,
    .bdrv_snapshot_list   = qemu_openvstorage_snap_list,
    .bdrv_snapshot_goto   = qemu_openvstorage_snap_rollback,

    .bdrv_create          = qemu_openvstorage_create,
    .create_opts          = &openvstorage_create_opts,
};

static BlockDriver bdrv_openvstorage_rdma = {
    .format_name          = "openvstorage",
    .protocol_name        = "openvstorage+rdma",
    .instance_size        = sizeof(BDRVOpenvStorageState),
    .bdrv_parse_filename  = qemu_openvstorage_parse_filename,

    .bdrv_file_open       = qemu_openvstorage_open,
    .bdrv_close           = qemu_openvstorage_close,
    .bdrv_getlength       = qemu_openvstorage_getlength,
    .bdrv_aio_readv       = qemu_openvstorage_aio_readv,
    .bdrv_aio_writev      = qemu_openvstorage_aio_writev,
    .bdrv_aio_flush       = qemu_openvstorage_aio_flush,
    .bdrv_has_zero_init   = bdrv_has_zero_init_1,

    .bdrv_snapshot_create = qemu_openvstorage_snap_create,
    .bdrv_snapshot_delete = qemu_openvstorage_snap_remove,
    .bdrv_snapshot_list   = qemu_openvstorage_snap_list,
    .bdrv_snapshot_goto   = qemu_openvstorage_snap_rollback,

    .bdrv_create          = qemu_openvstorage_create,
    .create_opts          = &openvstorage_create_opts,
};

static void bdrv_openvstorage_init(void)
{
    bdrv_register(&bdrv_openvstorage_shm);
    bdrv_register(&bdrv_openvstorage_tcp);
    bdrv_register(&bdrv_openvstorage_rdma);
}

block_init(bdrv_openvstorage_init);
