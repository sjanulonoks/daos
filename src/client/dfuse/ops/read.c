/**
 * (C) Copyright 2016-2019 Intel Corporation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * GOVERNMENT LICENSE RIGHTS-OPEN SOURCE SOFTWARE
 * The Government's rights to use, modify, reproduce, release, perform, display,
 * or disclose this software are subject to the terms of the Apache License as
 * provided in Contract No. B609815.
 * Any reproduction of computer software, computer software documentation, or
 * portions thereof marked with this legend must also reproduce the markings.
 */

#include "dfuse_common.h"
#include "dfuse.h"

#define READAHEAD_SIZE (1024 * 1024)

static void
dfuse_cb_read_complete(struct dfuse_event *ev)
{
	if (ev->de_ev.ev_error == 0)
		DFUSE_REPLY_BUF(ev, ev->de_req, ev->de_buff, ev->de_len);
	else
		DFUSE_REPLY_ERR_RAW(ev, ev->de_req,
				    daos_der2errno(ev->de_ev.ev_error));
	D_FREE(ev->de_buff);
}


void
dfuse_cb_read(fuse_req_t req, fuse_ino_t ino, size_t len, off_t position,
	      struct fuse_file_info *fi)
{
	struct dfuse_obj_hdl		*oh = (struct dfuse_obj_hdl *)fi->fh;
	struct dfuse_projection_info	*fs_handle = fuse_req_userdata(req);
	const struct fuse_ctx		*fc = fuse_req_ctx(req);
	d_iov_t				iov[2] = {};
	d_sg_list_t			sgl = {};
	struct fuse_bufvec		fb = {};
	daos_size_t			size;
	void				*buff;
	int				rc;
	size_t				buff_len = len;
	bool				skip_read = false;
	bool				readahead = false;
	struct dfuse_event		*ev = NULL;

	DFUSE_TRA_INFO(oh, "%#zx-%#zx requested pid=%d",
		       position, position + len - 1, fc->pid);

	if (oh->doh_ie->ie_truncated &&
	    position + len < oh->doh_ie->ie_stat.st_size &&
		((oh->doh_ie->ie_start_off == 0 &&
			oh->doh_ie->ie_end_off == 0) ||
			position >= oh->doh_ie->ie_end_off ||
			position + len <= oh->doh_ie->ie_start_off)) {
		off_t pos_ra = position + len + READAHEAD_SIZE;

		DFUSE_TRA_DEBUG(oh, "Returning zeros");
		skip_read = true;

		if (pos_ra <= oh->doh_ie->ie_stat.st_size &&
		    ((oh->doh_ie->ie_start_off == 0 &&
				oh->doh_ie->ie_end_off == 0) ||
				(position >= oh->doh_ie->ie_end_off ||
					pos_ra <= oh->doh_ie->ie_start_off))) {

			readahead = true;
		}
	} else if (oh->doh_ie->ie_dfs->dfs_attr_timeout > 0 &&
		len < (1024 * 1024) &&
		oh->doh_ie->ie_stat.st_size > (1024 * 1024)) {
		/* Only do readahead if the requested size is less than 1Mb and
		 * the file size is > 1Mb
		 */

		readahead = true;
	}

	if (readahead) {
		buff_len += READAHEAD_SIZE;
	} else {
		if (!skip_read) {
			D_ALLOC_PTR(ev);
			if (ev == NULL)
				D_GOTO(err, rc = ENOMEM);

			rc = daos_event_init(&ev->de_ev,
					     fs_handle->dpi_eq, NULL);
			if (rc != -DER_SUCCESS)
				D_GOTO(err, rc = daos_der2errno(rc));

			ev->de_req = req;
			ev->de_complete_cb = dfuse_cb_read_complete;
		}
	}

	D_ALLOC(buff, buff_len);
	if (!buff)
		D_GOTO(err, rc = ENOMEM);

	sgl.sg_nr = 1;
	d_iov_set(&iov[0], (void *)buff, buff_len);
	sgl.sg_iovs = iov;

	if (skip_read) {
		size = buff_len;
	} else {
		rc = dfs_read(oh->doh_dfs, oh->doh_obj, &sgl, position,
			ev ? &ev->de_len : &size,
			ev ? &ev->de_ev : NULL);
		if (rc != -DER_SUCCESS) {
			DFUSE_REPLY_ERR_RAW(oh, req, rc);
			D_FREE(buff);
			return;
		}
	}

	if (ev) {
		sem_post(&fs_handle->dpi_sem);
		return;
	}

	if (size <= len) {
		DFUSE_REPLY_BUF(oh, req, buff, size);
		D_FREE(buff);
		return;
	}

	rc = pthread_mutex_trylock(&oh->doh_ie->ie_dfs->dfs_read_mutex);
	if (rc == 0) {

		fb.count = 1;
		fb.buf[0].mem = buff + len;
		fb.buf[0].size = size - len;

		DFUSE_TRA_INFO(oh, "%#zx-%#zx was readahead",
			position + len, position + size - 1);

		rc = fuse_lowlevel_notify_store(fs_handle->dpi_info->di_session,
						ino, position + len, &fb, 0);
		if (rc == 0)
			DFUSE_TRA_DEBUG(oh, "notify_store returned %d", rc);
		else
			DFUSE_TRA_INFO(oh, "notify_store returned %d", rc);
		pthread_mutex_unlock(&oh->doh_ie->ie_dfs->dfs_read_mutex);
	}

	DFUSE_REPLY_BUF(oh, req, buff, len);
	D_FREE(buff);
	return;


err:
	D_FREE(ev);
	DFUSE_REPLY_ERR_RAW(oh, req, rc);
}
