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

//#ifdef HAVE_CONFIG_H
#include "config.h"
//#elif defined(_MSC_VER)
//#include "config-msvc.h"
//#endif

#include "syshead.h"

#include "status.h"
#include "perf.h"
#include "misc.h"
#include "fdmisc.h"

#include "memdbg.h"

/*
 * printf-style interface for outputting status info
 */

static const char *
print_status_mode(unsigned int flags)
{
    switch (flags)
    {
        case STATUS_OUTPUT_WRITE:
            return "WRITE";

        case STATUS_OUTPUT_READ:
            return "READ";

        case STATUS_OUTPUT_READ|STATUS_OUTPUT_WRITE:
            return "READ/WRITE";

        default:
            return "UNDEF";
    }
}

struct status_output *
status_open(const char *filename,
            const int refresh_freq,
            const int msglevel,
            const struct virtual_output *vout,
            const unsigned int flags)//分配空间 赋值并返回 可能会打开文件 生成输出状态信息
{
    struct status_output *so = NULL;
    if (filename || msglevel >= 0 || vout)
    {
        ALLOC_OBJ_CLEAR(so, struct status_output);//分配空间并置空
        so->flags = flags;
        so->msglevel = msglevel;
        so->vout = vout;
        so->fd = -1;
        buf_reset(&so->read_buf);
        event_timeout_clear(&so->et);//初始化参数成员
        if (filename)
        {
            switch (so->flags)
            {
                case STATUS_OUTPUT_WRITE:
                    so->fd = platform_open(filename,
                                           O_CREAT | O_TRUNC | O_WRONLY,
                                           S_IRUSR | S_IWUSR);//调用open（）
                    break;

                case STATUS_OUTPUT_READ:
                    so->fd = platform_open(filename,
                                           O_RDONLY,
                                           S_IRUSR | S_IWUSR);//调用open（）
                    break;

                case STATUS_OUTPUT_READ|STATUS_OUTPUT_WRITE:
                    so->fd = platform_open(filename,
                                           O_CREAT | O_RDWR,
                                           S_IRUSR | S_IWUSR);//调用open（）
                    break;

                default:
                    ASSERT(0);
            }
            if (so->fd >= 0)
            {
                so->filename = string_alloc(filename, NULL);//拷贝参数一到新开辟的堆空间 返回堆空间地址
                set_cloexec(so->fd);//设置文件描述符fork时关闭

                /* allocate read buffer */
                if (so->flags & STATUS_OUTPUT_READ)
                {
                    so->read_buf = alloc_buf(512);//分配堆空间
                }
            }
            else
            {
                msg(M_WARN, "Note: cannot open %s for %s", filename, print_status_mode(so->flags));
                so->errors = true;
            }
        }
        else
        {
            so->flags = STATUS_OUTPUT_WRITE;
        }

        if ((so->flags & STATUS_OUTPUT_WRITE) && refresh_freq > 0)
        {
            event_timeout_init(&so->et, refresh_freq, 0);//使用参数二三初始化参数一
        }
    }
    return so;
}

bool
status_trigger(struct status_output *so)
{
    if (so)
    {
        struct timeval null;
        CLEAR(null);
        return event_timeout_trigger(&so->et, &null, ETT_DEFAULT);
    }
    else
    {
        return false;
    }
}

bool
status_trigger_tv(struct status_output *so, struct timeval *tv)
{
    if (so)
    {
        return event_timeout_trigger(&so->et, tv, ETT_DEFAULT);
    }
    else
    {
        return false;
    }
}

void
status_reset(struct status_output *so)
{
    if (so && so->fd >= 0)
    {
        lseek(so->fd, (off_t)0, SEEK_SET);//文件偏移重置
    }
}

void
status_flush(struct status_output *so)//初始化参数
{
    if (so && so->fd >= 0 && (so->flags & STATUS_OUTPUT_WRITE))
    {
#if defined(HAVE_FTRUNCATE)
        {
            const off_t off = lseek(so->fd, (off_t)0, SEEK_CUR);
            if (ftruncate(so->fd, off) != 0)
            {
                msg(M_WARN | M_ERRNO, "Failed to truncate status file");
            }
        }
#elif defined(HAVE_CHSIZE)
        {
            const long off = (long) lseek(so->fd, (off_t)0, SEEK_CUR);
            chsize(so->fd, off);
        }
#else  /* if defined(HAVE_FTRUNCATE) */
#warning both ftruncate and chsize functions appear to be missing from this OS
#endif

        /* clear read buffer */
        if (buf_defined(&so->read_buf))//判断存在成功分配的堆空间
        {
            ASSERT(buf_init(&so->read_buf, 0));//初始化参数一
        }
    }
}

/* return false if error occurred */
bool
status_close(struct status_output *so)//关闭文件 释放参数 出错返回0
{
    bool ret = true;
    if (so)
    {
        if (so->errors)
        {
            ret = false;
        }
        if (so->fd >= 0)
        {
            if (close(so->fd) < 0)
            {
                ret = false;
            }
        }
        if (so->filename)
        {
            free(so->filename);
        }
        if (buf_defined(&so->read_buf))
        {
            free_buf(&so->read_buf);
        }
        free(so);
    }
    else
    {
        ret = false;
    }
    return ret;
}

#define STATUS_PRINTF_MAXLEN 512

void
status_printf(struct status_output *so, const char *format, ...)//格式化写文件 并调用虚拟接口
{
    if (so && (so->flags & STATUS_OUTPUT_WRITE))
    {
        char buf[STATUS_PRINTF_MAXLEN+2]; /* leave extra bytes for CR, LF */
        va_list arglist;
        int stat;

        va_start(arglist, format);
        stat = vsnprintf(buf, STATUS_PRINTF_MAXLEN, format, arglist);//库函数 格式化输出
        va_end(arglist);
        buf[STATUS_PRINTF_MAXLEN - 1] = 0;

        if (stat < 0 || stat >= STATUS_PRINTF_MAXLEN)
        {
            so->errors = true;
        }

        if (so->msglevel >= 0 && !so->errors)
        {
            msg(so->msglevel, "%s", buf);
        }

        if (so->fd >= 0 && !so->errors)
        {
            int len;
            strcat(buf, "\n");
            len = strlen(buf);
            if (len > 0)
            {
                if (write(so->fd, buf, len) != len)//写文件
                {
                    so->errors = true;
                }
            }
        }

        if (so->vout && !so->errors)
        {
            chomp(buf);//删除尾部的\r \r字符
            (*so->vout->func)(so->vout->arg, so->vout->flags_default, buf);//???
        }
    }
}

bool
status_read(struct status_output *so, struct buffer *buf)
{
    bool ret = false;

    if (so && so->fd >= 0 && (so->flags & STATUS_OUTPUT_READ))
    {
        ASSERT(buf_defined(&so->read_buf));
        ASSERT(buf_defined(buf));
        while (true)
        {
            const int c = buf_read_u8(&so->read_buf);

            /* read more of file into buffer */
            if (c == -1)
            {
                int len;

                ASSERT(buf_init(&so->read_buf, 0));
                len = read(so->fd, BPTR(&so->read_buf), BCAP(&so->read_buf));
                if (len <= 0)
                {
                    break;
                }

                ASSERT(buf_inc_len(&so->read_buf, len));
                continue;
            }

            ret = true;

            if (c == '\r')
            {
                continue;
            }

            if (c == '\n')
            {
                break;
            }

            buf_write_u8(buf, c);
        }

        buf_null_terminate(buf);
    }

    return ret;
}
