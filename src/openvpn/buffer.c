/*
 *  OpenVPN -- An application to securely tunnel IP networks
 *             over a single UDP port, with support for SSL/TLS-based
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

#include "common.h"
#include "buffer.h"
#include "error.h"
#include "mtu.h"
#include "misc.h"

#include "memdbg.h"

size_t
array_mult_safe(const size_t m1, const size_t m2, const size_t extra)//验证大小 返回参数一*参数二+参数三
{
    const size_t limit = 0xFFFFFFFF;
    unsigned long long res = (unsigned long long)m1 * (unsigned long long)m2 + (unsigned long long)extra;
    if (unlikely(m1 > limit) || unlikely(m2 > limit) || unlikely(extra > limit) || unlikely(res > (unsigned long long)limit))
    {
        msg(M_FATAL, "attemped allocation of excessively large array");
    }
    return (size_t) res;
}

void
buf_size_error(const size_t size)//输出错误信息
{
    msg(M_FATAL, "fatal buffer size error, size=%lu", (unsigned long)size);
}

struct buffer
#ifdef DMALLOC
alloc_buf_debug(size_t size, const char *file, int line)
#else
alloc_buf(size_t size)//给缓冲区结构体的成员分配参数大小的堆空间 并置空
#endif
{
    struct buffer buf;

    if (!buf_size_valid(size))//判断分配空间大小范围是否有效
    {
        buf_size_error(size);//输出错误信息
    }
    buf.capacity = (int)size;
    buf.offset = 0;
    buf.len = 0;
#ifdef DMALLOC
    buf.data = openvpn_dmalloc(file, line, size);
#else
    buf.data = calloc(1, size);//分配空间并置空
#endif
    check_malloc_return(buf.data);//检查 若为空 则输出信息 并退出

    return buf;
}

struct buffer
#ifdef DMALLOC
alloc_buf_gc_debug(size_t size, struct gc_arena *gc, const char *file, int line)
#else
alloc_buf_gc(size_t size, struct gc_arena *gc)  //返回局部缓冲区变量 内含已注册关联的堆空间信息
#endif
{
    struct buffer buf;
    if (!buf_size_valid(size))  //判断size是否小于可分配最大数值
    {
        buf_size_error(size);
    }
    buf.capacity = (int)size;
    buf.offset = 0;
    buf.len = 0;
#ifdef DMALLOC
    buf.data = (uint8_t *) gc_malloc_debug(size, false, gc, file, line);
#else
    buf.data = (uint8_t *) gc_malloc(size, false, gc);//分配空间 创建并关联垃圾回收条目 并返回数据区偏移地址
#endif
    if (size)
    {
        *buf.data = 0;
    }
    return buf;
}

struct buffer
#ifdef DMALLOC
clone_buf_debug(const struct buffer *buf, const char *file, int line)
#else
clone_buf(const struct buffer *buf)//拷贝参数及其成员空间 返回副本
#endif
{
    struct buffer ret;
    ret.capacity = buf->capacity;
    ret.offset = buf->offset;
    ret.len = buf->len;
#ifdef DMALLOC
    ret.data = (uint8_t *) openvpn_dmalloc(file, line, buf->capacity);
#else
    ret.data = (uint8_t *) malloc(buf->capacity);
#endif
    check_malloc_return(ret.data);
    memcpy(BPTR(&ret), BPTR(buf), BLEN(buf));
    return ret;
}

#ifdef BUF_INIT_TRACKING

bool
buf_init_debug(struct buffer *buf, int offset, const char *file, int line)
{
    buf->debug_file = file;
    buf->debug_line = line;
    return buf_init_dowork(buf, offset);
}

static inline int
buf_debug_line(const struct buffer *buf)
{
    return buf->debug_line;
}

static const char *
buf_debug_file(const struct buffer *buf)
{
    return buf->debug_file;
}

#else  /* ifdef BUF_INIT_TRACKING */

#define buf_debug_line(buf) 0
#define buf_debug_file(buf) "[UNDEF]"

#endif /* ifdef BUF_INIT_TRACKING */

void
buf_clear(struct buffer *buf)//置空并初始化参数成员
{
    if (buf->capacity > 0)
    {
        secure_memzero(buf->data, buf->capacity);//置空参数一空间
    }
    buf->len = 0;
    buf->offset = 0;
}

bool
buf_assign(struct buffer *dest, const struct buffer *src)//拷贝参数二道参数一中
{
    if (!buf_init(dest, src->offset))//初始化参数一
    {
        return false;
    }
    return buf_write(dest, BPTR(src), BLEN(src));//将参数三长度的参数二拷贝到参数一
}

struct buffer
clear_buf(void)
{
    struct buffer buf;
    CLEAR(buf);
    return buf;
}

void
free_buf(struct buffer *buf)//释放参数的缓冲区空间
{
    if (buf->data)
    {
        free(buf->data);
    }
    CLEAR(*buf);
}

/*
 * Return a buffer for write that is a subset of another buffer
 */
struct buffer
buf_sub(struct buffer *buf, int size, bool prepend)//返回一个用于写入的缓冲区，它是另一个缓冲区的子集
{
    struct buffer ret;
    uint8_t *data;

    CLEAR(ret);
    data = prepend ? buf_prepend(buf, size) : buf_write_alloc(buf, size);//???
    if (data)
    {
        ret.capacity = size;
        ret.data = data;
    }
    return ret;
}

/*
 * printf append to a buffer with overflow check
 */
bool
buf_printf(struct buffer *buf, const char *format, ...) //格式化输出（附加）到缓冲区中
{
    int ret = false;
    if (buf_defined(buf))   //判断存在成功分配的堆空间
    {
        va_list arglist;
        uint8_t *ptr = BEND(buf);   //返回当前当前缓冲区数据的结尾地址
        int cap = buf_forward_capacity(buf);    //返回当前缓冲区剩余空间大小

        if (cap > 0)    //有剩余空间
        {
            int stat;
            va_start(arglist, format);  //???可百度 库函数，找到可变参数第一个参数的栈地址
            stat = vsnprintf((char *)ptr, cap, format, arglist);    //将可变参数格式化输出到一个字符数组
            va_end(arglist);    //arglist=NULL
            *(buf->data + buf->capacity - 1) = 0; /* windows vsnprintf needs this */
            buf->len += (int) strlen((char *)ptr);  //更新缓冲区现有数据长度
            if (stat >= 0 && stat < cap)
            {
                ret = true;
            }
        }
    }
    return ret;
}

bool
buf_puts(struct buffer *buf, const char *str)//拷贝参数二信息到参数一的缓冲区成员中
{
    int ret = false;
    uint8_t *ptr = BEND(buf);//返回当前当前缓冲区数据结尾地址
    int cap = buf_forward_capacity(buf);//返回当前缓冲区剩余空间大小
    if (cap > 0)
    {
        strncpynt((char *)ptr,str, cap);
        *(buf->data + buf->capacity - 1) = 0; /* windows vsnprintf needs this */
        buf->len += (int) strlen((char *)ptr);
        ret = true;
    }
    return ret;
}


/*
 * This is necessary due to certain buggy implementations of snprintf,
 * that don't guarantee null termination for size > 0.
 *
 * Return false on overflow.
 *
 * This functionality is duplicated in src/openvpnserv/common.c
 * Any modifications here should be done to the other place as well.
 */

bool
openvpn_snprintf(char *str, size_t size, const char *format, ...)
{
    va_list arglist;
    int len = -1;
    if (size > 0)
    {
        va_start(arglist, format);
        len = vsnprintf(str, size, format, arglist);
        va_end(arglist);
        str[size - 1] = 0;
    }
    return (len >= 0 && len < size);
}

/*
 * write a string to the end of a buffer that was
 * truncated by buf_printf
 */
void
buf_catrunc(struct buffer *buf, const char *str)
{
    if (buf_forward_capacity(buf) <= 1)
    {
        int len = (int) strlen(str) + 1;
        if (len < buf_forward_capacity_total(buf))
        {
            strncpynt((char *)(buf->data + buf->capacity - len), str, len);
        }
    }
}

/*
 * convert a multi-line output to one line
 */
void
convert_to_one_line(struct buffer *buf)
{
    uint8_t *cp = BPTR(buf);
    int len = BLEN(buf);
    while (len--)
    {
        if (*cp == '\n')
        {
            *cp = '|';
        }
        ++cp;
    }
}

/* NOTE: requires that string be null terminated */
void
buf_write_string_file(const struct buffer *buf, const char *filename, int fd)
{
    const int len = strlen((char *) BPTR(buf));
    const int size = write(fd, BPTR(buf), len);
    if (size != len)
    {
        msg(M_ERR, "Write error on file '%s'", filename);
    }
}

/*
 * Garbage collection
 */

void *
#ifdef DMALLOC
gc_malloc_debug(size_t size, bool clear, struct gc_arena *a, const char *file, int line)
#else
gc_malloc(size_t size, bool clear, struct gc_arena *a)  //分配空间 创建并关联垃圾回收条目 并返回数据区偏移地址
#endif
{
    void *ret;
    if (a)
    {
        struct gc_entry *e;
#ifdef DMALLOC
        e = (struct gc_entry *) openvpn_dmalloc(file, line, size + sizeof(struct gc_entry));
#else
        e = (struct gc_entry *) malloc(size + sizeof(struct gc_entry));
#endif
        check_malloc_return(e);     //检查 若为空 则输出信息 并退出
        ret = (char *) e + sizeof(struct gc_entry);     //回收条目中 数据开始的偏移地址
        e->next = a->list;      //保存原有的第一个条目
        a->list = e;        //插入新条目
    }
    else
    {
#ifdef DMALLOC
        ret = openvpn_dmalloc(file, line, size);
#else
        ret = malloc(size);
#endif
        check_malloc_return(ret);
    }
#ifndef ZERO_BUFFER_ON_ALLOC
    if (clear)
#endif
    memset(ret, 0, size);
    return ret;
}

void
x_gc_free(struct gc_arena *a)//释放空间
{
    struct gc_entry *e;
    e = a->list;
    a->list = NULL;

    while (e != NULL)
    {
        struct gc_entry *next = e->next;
        free(e);
        e = next;
    }
}

/*
 * Functions to handle special objects in gc_entries
 */

void
x_gc_freespecial(struct gc_arena *a)//使用特定函数释放空间
{
    struct gc_entry_special *e;
    e = a->list_special;
    a->list_special = NULL;

    while (e != NULL)
    {
        struct gc_entry_special *next = e->next;
        e->free_fnc(e->addr);
        free(e);
        e = next;
    }
}

void
gc_addspecial(void *addr, void(free_function)(void *), struct gc_arena *a)//将参数一参数二存入堆空间并插入参数三的链表中
{
    ASSERT(a);
    struct gc_entry_special *e;
#ifdef DMALLOC
    e = (struct gc_entry_special *) openvpn_dmalloc(file, line, sizeof(struct gc_entry_special));
#else
    e = (struct gc_entry_special *) malloc(sizeof(struct gc_entry_special));//分配空间
#endif
    check_malloc_return(e);//检查 若为空 则输出信息 并退出
    e->free_fnc = free_function;
    e->addr = addr;

    e->next = a->list_special;
    a->list_special = e;//插入链表中
}


/*
 * Transfer src arena to dest, resetting src to an empty arena.
 */
void
gc_transfer(struct gc_arena *dest, struct gc_arena *src)
{
    if (dest && src)
    {
        struct gc_entry *e = src->list;
        if (e)
        {
            while (e->next != NULL)
            {
                e = e->next;
            }
            e->next = dest->list;
            dest->list = src->list;
            src->list = NULL;
        }
    }
}

/*
 * Hex dump -- Output a binary buffer to a hex string and return it.
 */

char *
format_hex_ex(const uint8_t *data, int size, int maxoutput,
              unsigned int space_break_flags, const char *separator,
              struct gc_arena *gc)
{
    const size_t bytes_per_hexblock = space_break_flags & FHE_SPACE_BREAK_MASK;
    const size_t separator_len = separator ? strlen(separator) : 0;
    static_assert(INT_MAX <= SIZE_MAX, "Code assumes INT_MAX <= SIZE_MAX");
    const size_t out_len = maxoutput > 0 ? maxoutput :
                           ((size * 2) + ((size / bytes_per_hexblock) * separator_len) + 2);

    struct buffer out = alloc_buf_gc(out_len, gc);
    for (int i = 0; i < size; ++i)
    {
        if (separator && i && !(i % bytes_per_hexblock))
        {
            buf_printf(&out, "%s", separator);
        }
        if (space_break_flags & FHE_CAPS)
        {
            buf_printf(&out, "%02X", data[i]);
        }
        else
        {
            buf_printf(&out, "%02x", data[i]);
        }
    }
    buf_catrunc(&out, "[more...]");
    return (char *)out.data;
}

/*
 * remove specific trailing character
 */

void
buf_rmtail(struct buffer *buf, uint8_t remove)
{
    uint8_t *cp = BLAST(buf);
    if (cp && *cp == remove)
    {
        *cp = '\0';
        --buf->len;
    }
}

/*
 * force a null termination even it requires
 * truncation of the last char.
 */
void
buf_null_terminate(struct buffer *buf)//强制一个零终止，即使它需要截断最后一个字符。
{
    char *last = (char *) BLAST(buf);
    if (last && *last == '\0') /* already terminated? */
    {
        return;
    }

    if (!buf_safe(buf, 1))   /* make space for trailing null */
    {
        buf_inc_len(buf, -1);
    }

    buf_write_u8(buf, 0);
}

/*
 * Remove trailing \r and \n chars and ensure
 * null termination. 删除尾部回车换行字符，确保空终止
 */
void
buf_chomp(struct buffer *buf)//删除尾部回车换行字符，确保空终止
{
    while (true)
    {
        char *last = (char *) BLAST(buf);//返回结尾字符地址
        if (!last)
        {
            break;
        }
        if (char_class(*last, CC_CRLF|CC_NULL))//根据字符类型对字符串进行分类和更改
        {
            if (!buf_inc_len(buf, -1))//缓冲区字符串长度-1
            {
                break;
            }
        }
        else
        {
            break;
        }
    }
    buf_null_terminate(buf);//强制一个零终止，即使它需要截断最后一个字符。
}

const char *
skip_leading_whitespace(const char *str)
{
    while (*str)
    {
        const char c = *str;
        if (!(c == ' ' || c == '\t'))
        {
            break;
        }
        ++str;
    }
    return str;
}

/*
 * like buf_null_terminate, but operate on strings
 */
void
string_null_terminate(char *str, int len, int capacity)
{
    ASSERT(len >= 0 && len <= capacity && capacity > 0);
    if (len < capacity)
    {
        *(str + len) = '\0';
    }
    else if (len == capacity)
    {
        *(str + len - 1) = '\0';
    }
}

/*
 * Remove trailing \r and \n chars.
 */
void
chomp(char *str)//删除尾部的\r \r字符
{
    rm_trailing_chars(str, "\r\n");//删除参数一尾部的参数二字符
}

/*
 * Remove trailing chars
 */
void
rm_trailing_chars(char *str, const char *what_to_delete)//删除参数一尾部的参数二字符
{
    bool modified;
    do
    {
        const int len = strlen(str);
        modified = false;
        if (len > 0)
        {
            char *cp = str + (len - 1);
            if (strchr(what_to_delete, *cp) != NULL)//返回参数二在参数一中出现的地址
            {
                *cp = '\0';
                modified = true;
            }
        }
    } while (modified);
}

/*
 * Allocate a string
 */
char *
#ifdef DMALLOC
string_alloc_debug(const char *str, struct gc_arena *gc, const char *file, int line)
#else
string_alloc(const char *str, struct gc_arena *gc)//拷贝参数一到新开辟的堆空间 返回堆空间地址
#endif
{
    if (str)
    {
        const int n = strlen(str) + 1;
        char *ret;

        if (gc)
        {
#ifdef DMALLOC
            ret = (char *) gc_malloc_debug(n, false, gc, file, line);
#else
            ret = (char *) gc_malloc(n, false, gc);//分配空间 创建并关联垃圾回收条目 并返回数据区偏移地址
#endif
        }
        else
        {
            /* If there are no garbage collector available, it's expected
             * that the caller cleans up afterwards.  This is coherent with the
             * earlier behaviour when gc_malloc() would be called with gc == NULL
             */
#ifdef DMALLOC
            ret = openvpn_dmalloc(file, line, n);
            memset(ret, 0, n);
#else
            ret = calloc(1, n);
#endif
            check_malloc_return(ret);//检查 若为空 则输出信息 并退出
        }
        memcpy(ret, str, n);//拷贝str到新开辟的堆空间
        return ret;
    }
    else
    {
        return NULL;
    }
}

/*
 * Erase all characters in a string
 */
void
string_clear(char *str)
{
    if (str)
    {
        secure_memzero(str, strlen(str));
    }
}

/*
 * Return the length of a string array
 */
int
string_array_len(const char **array)
{
    int i = 0;
    if (array)
    {
        while (array[i])
        {
            ++i;
        }
    }
    return i;
}

char *
print_argv(const char **p, struct gc_arena *gc, const unsigned int flags)
{
    struct buffer out = alloc_buf_gc(256, gc);
    int i = 0;
    for (;; )
    {
        const char *cp = *p++;
        if (!cp)
        {
            break;
        }
        if (i)
        {
            buf_printf(&out, " ");
        }
        if (flags & PA_BRACKET)
        {
            buf_printf(&out, "[%s]", cp);
        }
        else
        {
            buf_printf(&out, "%s", cp);
        }
        ++i;
    }
    return BSTR(&out);
}

/*
 * Allocate a string inside a buffer
 */
struct buffer
#ifdef DMALLOC
string_alloc_buf_debug(const char *str, struct gc_arena *gc, const char *file, int line)
#else
string_alloc_buf(const char *str, struct gc_arena *gc)
#endif
{
    struct buffer buf;

    ASSERT(str);

#ifdef DMALLOC
    buf_set_read(&buf, (uint8_t *) string_alloc_debug(str, gc, file, line), strlen(str) + 1);
#else
    buf_set_read(&buf, (uint8_t *) string_alloc(str, gc), strlen(str) + 1);
#endif

    if (buf.len > 0) /* Don't count trailing '\0' as part of length */
    {
        --buf.len;
    }

    return buf;
}

/*
 * String comparison
 */

bool
buf_string_match_head_str(const struct buffer *src, const char *match)
{
    const int size = strlen(match);
    if (size < 0 || size > src->len)
    {
        return false;
    }
    return memcmp(BPTR(src), match, size) == 0;
}

bool
buf_string_compare_advance(struct buffer *src, const char *match)
{
    if (buf_string_match_head_str(src, match))
    {
        buf_advance(src, strlen(match));
        return true;
    }
    else
    {
        return false;
    }
}

int
buf_substring_len(const struct buffer *buf, int delim)//返回参数二在参数一中的位置
{
    int i = 0;
    struct buffer tmp = *buf;
    int c;

    while ((c = buf_read_u8(&tmp)) >= 0)//返回预读空间起始地址 并跳到下一个字符
    {
        ++i;
        if (c == delim)//找到字符为止
        {
            return i;
        }
    }
    return -1;
}

/*
 * String parsing
 */

bool
buf_parse(struct buffer *buf, const int delim, char *line, const int size)
{
    bool eol = false;
    int n = 0;
    int c;

    ASSERT(size > 0);

    do
    {
        c = buf_read_u8(buf);
        if (c < 0)
        {
            eol = true;
        }
        if (c <= 0 || c == delim)
        {
            c = 0;
        }
        if (n >= size)
        {
            break;
        }
        line[n++] = c;
    }
    while (c);

    line[size-1] = '\0';
    return !(eol && !strlen(line));
}

/*
 * Print a string which might be NULL
 */
const char *
np(const char *str)
{
    if (str)
    {
        return str;
    }
    else
    {
        return "[NULL]";
    }
}

/*
 * Classify and mutate strings based on character types.
 */
//根据字符类型对字符串进行分类和更改
bool
char_class(const unsigned char c, const unsigned int flags)
{
    if (!flags)
    {
        return false;
    }
    if (flags & CC_ANY)
    {
        return true;
    }

    if ((flags & CC_NULL) && c == '\0')
    {
        return true;
    }

    if ((flags & CC_ALNUM) && isalnum(c))
    {
        return true;
    }
    if ((flags & CC_ALPHA) && isalpha(c))
    {
        return true;
    }
    if ((flags & CC_ASCII) && isascii(c))
    {
        return true;
    }
    if ((flags & CC_CNTRL) && iscntrl(c))
    {
        return true;
    }
    if ((flags & CC_DIGIT) && isdigit(c))
    {
        return true;
    }
    if ((flags & CC_PRINT) && (c >= 32 && c != 127)) /* allow ascii non-control and UTF-8, consider DEL to be a control */
    {
        return true;
    }
    if ((flags & CC_PUNCT) && ispunct(c))
    {
        return true;
    }
    if ((flags & CC_SPACE) && isspace(c))
    {
        return true;
    }
    if ((flags & CC_XDIGIT) && isxdigit(c))
    {
        return true;
    }

    if ((flags & CC_BLANK) && (c == ' ' || c == '\t'))
    {
        return true;
    }
    if ((flags & CC_NEWLINE) && c == '\n')
    {
        return true;
    }
    if ((flags & CC_CR) && c == '\r')
    {
        return true;
    }

    if ((flags & CC_BACKSLASH) && c == '\\')
    {
        return true;
    }
    if ((flags & CC_UNDERBAR) && c == '_')
    {
        return true;
    }
    if ((flags & CC_DASH) && c == '-')
    {
        return true;
    }
    if ((flags & CC_DOT) && c == '.')
    {
        return true;
    }
    if ((flags & CC_COMMA) && c == ',')
    {
        return true;
    }
    if ((flags & CC_COLON) && c == ':')
    {
        return true;
    }
    if ((flags & CC_SLASH) && c == '/')
    {
        return true;
    }
    if ((flags & CC_SINGLE_QUOTE) && c == '\'')
    {
        return true;
    }
    if ((flags & CC_DOUBLE_QUOTE) && c == '\"')
    {
        return true;
    }
    if ((flags & CC_REVERSE_QUOTE) && c == '`')
    {
        return true;
    }
    if ((flags & CC_AT) && c == '@')
    {
        return true;
    }
    if ((flags & CC_EQUAL) && c == '=')
    {
        return true;
    }
    if ((flags & CC_LESS_THAN) && c == '<')
    {
        return true;
    }
    if ((flags & CC_GREATER_THAN) && c == '>')
    {
        return true;
    }
    if ((flags & CC_PIPE) && c == '|')
    {
        return true;
    }
    if ((flags & CC_QUESTION_MARK) && c == '?')
    {
        return true;
    }
    if ((flags & CC_ASTERISK) && c == '*')
    {
        return true;
    }

    return false;
}

static inline bool
char_inc_exc(const char c, const unsigned int inclusive, const unsigned int exclusive)//判断字符c是否属于参数二,不属于参数三
{
    return char_class(c, inclusive) && !char_class(c, exclusive);//根据字符类型对字符串进行分类和更改
}

bool
string_class(const char *str, const unsigned int inclusive, const unsigned int exclusive)
{
    char c;
    ASSERT(str);
    while ((c = *str++))
    {
        if (!char_inc_exc(c, inclusive, exclusive))
        {
            return false;
        }
    }
    return true;
}

/*
 * Modify string in place.
 * Guaranteed to not increase string length.
 */
//对参数一字符串进行检查替换 不变更长度
bool
string_mod(char *str, const unsigned int inclusive, const unsigned int exclusive, const char replace)
{
    const char *in = str;
    bool ret = true;

    ASSERT(str);

    while (true)
    {
        char c = *in++;
        if (c)
        {
            if (!char_inc_exc(c, inclusive, exclusive))//判断字符c是否属于参数二,不属于参数三
            {
                c = replace;
                ret = false;
            }
            if (c)
            {
                *str++ = c;
            }
        }
        else
        {
            *str = '\0';
            break;
        }
    }
    return ret;
}

const char *
string_mod_const(const char *str,
                 const unsigned int inclusive,
                 const unsigned int exclusive,
                 const char replace,
                 struct gc_arena *gc)//对参数一字符串的副本进行检查替换 不变更长度 返回副本地址
{
    if (str)
    {
        char *buf = string_alloc(str, gc);//拷贝参数一到新开辟的堆空间 返回地址
        string_mod(buf, inclusive, exclusive, replace);//对参数一字符串进行检查替换 不变更长度
        return buf;
    }
    else
    {
        return NULL;
    }
}

void
string_replace_leading(char *str, const char match, const char replace)
{
    ASSERT(match != '\0');
    while (*str)
    {
        if (*str == match)
        {
            *str = replace;
        }
        else
        {
            break;
        }
        ++str;
    }
}

#ifdef CHARACTER_CLASS_DEBUG

#define CC_INCLUDE    (CC_PRINT)
#define CC_EXCLUDE    (0)
#define CC_REPLACE    ('.')

void
character_class_debug(void)
{
    char buf[256];

    while (fgets(buf, sizeof(buf), stdin) != NULL)
    {
        string_mod(buf, CC_INCLUDE, CC_EXCLUDE, CC_REPLACE);
        printf("%s", buf);
    }
}

#endif

#ifdef VERIFY_ALIGNMENT
void
valign4(const struct buffer *buf, const char *file, const int line)
{
    if (buf && buf->len)
    {
        int msglevel = D_ALIGN_DEBUG;
        const unsigned int u = (unsigned int) BPTR(buf);

        if (u & (PAYLOAD_ALIGN-1))
        {
            msglevel = D_ALIGN_ERRORS;
        }

        msg(msglevel, "%sAlignment at %s/%d ptr=" ptr_format " OLC=%d/%d/%d I=%s/%d",
            (msglevel == D_ALIGN_ERRORS) ? "ERROR: " : "",
            file,
            line,
            (ptr_type)buf->data,
            buf->offset,
            buf->len,
            buf->capacity,
            buf_debug_file(buf),
            buf_debug_line(buf));
    }
}
#endif /* ifdef VERIFY_ALIGNMENT */

/*
 * struct buffer_list
 */
struct buffer_list *
buffer_list_new(const int max_size)//分配空间并设置参数的值给成员
{
    struct buffer_list *ret;
    ALLOC_OBJ_CLEAR(ret, struct buffer_list);//分配空间并置空
    ret->max_size = max_size;
    ret->size = 0;
    return ret;
}

void
buffer_list_free(struct buffer_list *ol)//释放参数及成员空间
{
    if (ol)
    {
        buffer_list_reset(ol);//释放参数指向的所有链表缓冲区空间 并置空成员指针
        free(ol);
    }
}

bool
buffer_list_defined(const struct buffer_list *ol)//参数不为空 且有头条目 返回1
{
    return ol && ol->head != NULL;
}

void
buffer_list_reset(struct buffer_list *ol)//释放参数指向的所有链表缓冲区空间 并置空成员指针
{
    struct buffer_entry *e = ol->head;
    while (e)
    {
        struct buffer_entry *next = e->next;
        free_buf(&e->buf);//释放参数的缓冲区空间
        free(e);
        e = next;//迭代
    }
    ol->head = ol->tail = NULL;
    ol->size = 0;
}

void
buffer_list_push(struct buffer_list *ol, const unsigned char *str)//将参数二拷贝到新条目空间中 并插入到参数一尾部
{
    if (str)
    {
        const size_t len = strlen((const char *)str);
        struct buffer_entry *e = buffer_list_push_data(ol, str, len+1);//将参数三大小的参数二拷贝到新条目空间中 并插入到参数一尾部
        if (e)
        {
            e->buf.len = len; /* Don't count trailing '\0' as part of length 去除尾部的0*/
        }
    }
}

struct buffer_entry *
buffer_list_push_data(struct buffer_list *ol, const uint8_t *data, size_t size)//将参数三大小的参数二拷贝到新条目空间中 并插入到参数一尾部
{
    struct buffer_entry *e = NULL;
    if (data && (!ol->max_size || ol->size < ol->max_size))
    {
        ALLOC_OBJ_CLEAR(e, struct buffer_entry);//分配空间并置空

        ++ol->size;//递增当前条目数
        if (ol->tail)
        {
            ASSERT(ol->head);
            ol->tail->next = e;//在尾部插入下一个节点
        }
        else
        {
            ASSERT(!ol->head);
            ol->head = e;//否则 是为头节点
        }
        e->buf = alloc_buf(size);//给缓冲区结构体的成员分配参数大小的堆空间 并置空
        memcpy(e->buf.data, data, size);//拷贝
        e->buf.len = (int)size;
        ol->tail = e;
    }
    return e;
}

struct buffer *
buffer_list_peek(struct buffer_list *ol)//返回参数成员的头节点缓冲区
{
    if (ol && ol->head)
    {
        return &ol->head->buf;
    }
    else
    {
        return NULL;
    }
}

void
buffer_list_aggregate_separator(struct buffer_list *bl, const size_t max, const char *sep)
{
    int sep_len = strlen(sep);

    if (bl->head)
    {
        struct buffer_entry *more = bl->head;
        size_t size = 0;
        int count = 0;
        for (count = 0; more && size <= max; ++count)
        {
            size += BLEN(&more->buf) + sep_len;
            more = more->next;
        }

        if (count >= 2)
        {
            int i;
            struct buffer_entry *e = bl->head, *f;

            ALLOC_OBJ_CLEAR(f, struct buffer_entry);//分配空间并置空
            f->buf.data = malloc(size);
            check_malloc_return(f->buf.data);
            f->buf.capacity = size;
            for (i = 0; e && i < count; ++i)
            {
                struct buffer_entry *next = e->next;
                buf_copy(&f->buf, &e->buf);
                buf_write(&f->buf, sep, sep_len);
                free_buf(&e->buf);
                free(e);
                e = next;
            }
            bl->head = f;
            f->next = more;
            if (!more)
            {
                bl->tail = f;
            }
        }
    }
}

void
buffer_list_aggregate(struct buffer_list *bl, const size_t max)
{
    buffer_list_aggregate_separator(bl, max, "");
}

void
buffer_list_pop(struct buffer_list *ol)//弹出链表头节点
{
    if (ol && ol->head)
    {
        struct buffer_entry *e = ol->head->next;
        free_buf(&ol->head->buf);//释放内部空间
        free(ol->head);//释放头节点
        ol->head = e;//头节点后移
        --ol->size;
        if (!e)
        {
            ol->tail = NULL;
        }
    }
}

void
buffer_list_advance(struct buffer_list *ol, int n)//弹出链表头节点
{
    if (ol->head)
    {
        struct buffer *buf = &ol->head->buf;
        ASSERT(buf_advance(buf, n));
        if (!BLEN(buf))//返回当前缓冲区的内部数据长度
        {
            buffer_list_pop(ol);//弹出链表头节点
        }
    }
}

struct buffer_list *
buffer_list_file(const char *fn, int max_line_len)
{
    FILE *fp = platform_fopen(fn, "r");
    struct buffer_list *bl = NULL;

    if (fp)
    {
        char *line = (char *) malloc(max_line_len);
        if (line)
        {
            bl = buffer_list_new(0);
            while (fgets(line, max_line_len, fp) != NULL)
            {
                buffer_list_push(bl, (unsigned char *)line);
            }
            free(line);
        }
        fclose(fp);
    }
    return bl;
}
