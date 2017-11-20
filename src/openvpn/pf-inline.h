/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single TCP/UDP port, with support for SSL/TLS-based
 *             session authentication and key exchange,
 *             packet encryption, packet authentication, and
 *             packet compression.
 *
 *  Copyright (C) 2002-2017 OpenVPN Technologies, Inc. <sales@openvpn.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include "config.h"     //增加 --liut 171116
#if defined(ENABLE_PF) && !defined(PF_INLINE_H)
#define PF_INLINE_H

/*
 * Inline functions
 */

#define PCT_SRC  1
#define PCT_DEST 2
static inline bool
pf_c2c_test(const struct context *src, const struct context *dest, const char *prefix)
{
    bool pf_cn_test(struct pf_set *pfs, const struct tls_multi *tm, const int type, const char *prefix);

    return (!src->c2.pf.enabled  || pf_cn_test(src->c2.pf.pfs,  dest->c2.tls_multi, PCT_DEST, prefix))
           && (!dest->c2.pf.enabled || pf_cn_test(dest->c2.pf.pfs, src->c2.tls_multi,  PCT_SRC,  prefix));
}

static inline bool
pf_addr_test(const struct context *src, const struct mroute_addr *dest, const char *prefix)
{
    bool pf_addr_test_dowork(const struct context *src, const struct mroute_addr *dest, const char *prefix);

    if (src->c2.pf.enabled)
    {
        return pf_addr_test_dowork(src, dest, prefix);
    }
    else
    {
        return true;
    }
}

static inline bool
pf_kill_test(const struct pf_set *pfs)
{
    return pfs->kill;
}

#endif /* if defined(ENABLE_PF) && !defined(PF_INLINE_H) */