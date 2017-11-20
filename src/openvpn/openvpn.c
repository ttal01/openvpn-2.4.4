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

#include "init.h"
#include "forward.h"
#include "multi.h"
#include "win32.h"
#include "platform.h"

#include "memdbg.h"

#include "forward-inline.h"

#define P2P_CHECK_SIG() EVENT_LOOP_CHECK_SIGNAL(c, process_signal_p2p, c);

static bool
process_signal_p2p(struct context *c)//信号处理
{
    remap_signal(c);//处理信号值
    return process_signal(c);//信号各种处理
}

/* Write our PID to a file */
static void
write_pid(const char *filename)//写pid到文件
{
    if (filename)
    {
        unsigned int pid = 0;
        FILE *fp = platform_fopen(filename, "w");//打开文件
        if (!fp)
        {
            msg(M_ERR, "Open error on pid file %s", filename);
        }

        pid = platform_getpid();
        fprintf(fp, "%u\n", pid);
        if (fclose(fp))
        {
            msg(M_ERR, "Close error on pid file %s", filename);
        }
    }
}


/**************************************************************************/
/**
 * Main event loop for OpenVPN in client mode, where only one VPN tunnel
 * is active.
 * @ingroup eventloop
 *
 * @param c - The context structure of the single active VPN tunnel.
 */
static void
tunnel_point_to_point(struct context *c) //客户端模式下的OpenVPN主事件循环，只有一个VPN隧道是活动的。
{
    context_clear_2(c);//置空level_2上下文结构体

    /* set point-to-point mode */
    c->mode = CM_P2P;

    /* initialize tunnel instance */
    init_instance_handle_signals(c, c->es, CC_HARD_USR1_TO_HUP);//初始化一个隧道实例，处理pre - init信号设置
    if (IS_SIG(c))
    {
        return;
    }

    /* main event loop */
    while (true)//主循环
    {
        perf_push(PERF_EVENT_LOOP);//空函数体

        /* process timers, TLS, etc. */
        pre_select(c);//定时器的设定与相关处理
        P2P_CHECK_SIG();//在事件循环中检查信号

        /* set up and do the I/O wait */
        io_wait(c, p2p_iow_flags(c));//内核I/O等待函数，用于所有I/O等待，除了服务器模式的TCP
        P2P_CHECK_SIG();//在事件循环中检查信号

        /* timeout? */
        if (c->c2.event_set_status == ES_TIMEOUT)
        {
            perf_pop();//空函数体
            continue;
        }

        /* process the I/O which triggered select 处理触发选择的I/O*/
        process_io(c);//处理IO
        P2P_CHECK_SIG();//在事件循环中检查信号

        perf_pop();//空函数体
    }

    uninit_management_callback();

    /* tear down tunnel instance (unless --persist-tun) */
    close_instance(c);//关闭一个隧道实例
}

#undef PROCESS_SIGNAL_P2P


/**************************************************************************/
/**
 * OpenVPN's main init-run-cleanup loop.
 * @ingroup eventloop
 *
 * This function contains the two outer OpenVPN loops.  Its structure is
 * as follows:
 *  - Once-per-process initialization.
 *  - Outer loop, run at startup and then once per \c SIGHUP:
 *    - Level 1 initialization
 *    - Inner loop, run at startup and then once per \c SIGUSR1:
 *      - Call event loop function depending on client or server mode:
 *        - \c tunnel_point_to_point()
 *        - \c tunnel_server()
 *    - Level 1 cleanup
 *  - Once-per-process cleanup.
 *
 * @param argc - Commandline argument count.
 * @param argv - Commandline argument values.
 */
static
int
openvpn_main(int argc, char *argv[])
{
    struct context c;	//包含通道中所有信息的结构体

#if PEDANTIC
    fprintf(stderr, "Sorry, I was built with --enable-pedantic and I am incapable of doing any real work!\n");
    return 1;
#endif

#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif

    CLEAR(c);	//置空

    /* signify first time for components which can
     * only be initialized once per program instantiation.对于只能在每个程序实例化时初始化的组件来说，这是第一次 */
    c.first_time = true;

    /* initialize program-wide statics */
    if (init_static())//静态 全局等变量初始化
    {
        /*
         * This loop is initially executed on startup and then
         * once per SIGHUP.
         */
        do
        {
            /* enter pre-initialization mode with regard to signal handling */
            pre_init_signal_catch();	//注册信号处理函数，在处理函数中保存信号值等信息

            /* zero context struct but leave first_time member alone */
            context_clear_all_except_first_time(&c);	//除了fist_time、persist成员，其它置空

            /* static signal info object */
            CLEAR(siginfo_static);		//将储存信号信息的内存置空
            c.sig = &siginfo_static;	//绑定到通道结构体成员上

            /* initialize garbage collector scoped to context object 初始化垃圾收集器的作用域为上下文对象*/
            gc_init(&c.gc);//初始化

            /* initialize environmental variable store 初始化环境变量存储*/
            c.es = env_set_create(NULL);
#ifdef _WIN32
            set_win_sys_path_via_env(c.es);
#endif

#ifdef ENABLE_MANAGEMENT
            /* initialize management subsystem */
            init_management(&c);	//管理对象初始化
#endif

            /* initialize options to default state */
            init_options(&c.options, true);		//命令行选项初始化

            /* parse command line options, and read configuration file */
            parse_argv(&c.options, argc, argv, M_USAGE, OPT_P_DEFAULT, NULL, c.es);//逐个解析命令行所有命令选项 并设置

#ifdef ENABLE_PLUGIN
            /* plugins may contribute options configuration */
            init_verb_mute(&c, IVM_LEVEL_1);
            init_plugins(&c);
            open_plugins(&c, true, OPENVPN_PLUGIN_INIT_PRE_CONFIG_PARSE);
#endif

            /* init verbosity and mute levels */
            init_verb_mute(&c, IVM_LEVEL_1);

            /* set dev options */
            init_options_dev(&c.options);//--dev-node 选择的处理方式

            /* openssl print info? */
            if (print_openssl_info(&c.options))
            {
                break;
            }

            /* --genkey mode? */
            if (do_genkey(&c.options))
            {
                break;
            }

            /* tun/tap persist command? */
            if (do_persist_tuntap(&c.options))//持续的TUN/TAP设备管理模式
            {
                break;
            }

            /* sanity check on options */
            options_postprocess(&c.options);//选项结构体成员的后处理、核查及各文件权限确认

            /* show all option settings */
            show_settings(&c.options);//输出各种类型信息

            /* print version number */
            msg(M_INFO, "%s", title_string);
#ifdef _WIN32
            show_windows_version(M_INFO);
#endif
            show_library_versions(M_INFO);//打印版本信息

            /* misc stuff */
            pre_setup(&c.options);//???

            /* test crypto? */
            if (do_test_crypto(&c.options))
            {
                break;
            }

            /* Query passwords before becoming a daemon if we don't use the
             * management interface to get them. */
#ifdef ENABLE_MANAGEMENT
            if (!(c.options.management_flags & MF_QUERY_PASSWORDS))
#endif
            init_query_passwords(&c);//查询私钥和auth- user- pass用户名/密码

            /* become a daemon if --daemon */
            if (c.first_time)
            {
                c.did_we_daemonize = possibly_become_daemon(&c.options);//变为守护进程的相关设置
                write_pid(c.options.writepid);//写pid到文件
            }

#ifdef ENABLE_MANAGEMENT
            /* open management subsystem 开放管理子系统*/
            if (!open_management(&c))//开放管理子系统 含 监听/连接套接字
            {
                break;
            }
            /* query for passwords through management interface, if needed */
            if (c.options.management_flags & MF_QUERY_PASSWORDS)
            {
                init_query_passwords(&c);
            }
#endif

            /* set certain options as environmental variables */
            setenv_settings(c.es, &c.options);//将配置、连接信息按"%s=%s"格式添加到参数一（环境变量配置）所含链表中

            /* finish context init */
            context_init_1(&c);//置空level_1上下文结构体 复位连接链表 还可能随机打乱链表顺序

            do
            {
                /* run tunnel depending on mode */
                switch (c.options.mode)
                {
                    case MODE_POINT_TO_POINT:
                        tunnel_point_to_point(&c);//客户端模式下的OpenVPN主事件循环，只有一个VPN隧道是活动的
                        break;

#if P2MP_SERVER
                    case MODE_SERVER:
                        tunnel_server(&c);
                        break;

#endif
                    default:
                        ASSERT(0);
                }

                /* indicates first iteration -- has program-wide scope 表示第一次迭代——具有程序范围*/
                c.first_time = false;

                /* any signals received? */
                if (IS_SIG(&c))
                {
                    print_signal(c.sig, NULL, M_INFO);//打印接收到的信号信息
                }

                /* pass restart status to management subsystem */
                signal_restart_status(c.sig);//将重启状态传递给管理子系统
            }
            while (c.sig->signal_received == SIGUSR1);

            uninit_options(&c.options);
            gc_reset(&c.gc);
        }
        while (c.sig->signal_received == SIGHUP);
    }

    context_gc_free(&c);//释放垃圾回收器

    env_set_destroy(c.es);//释放环境变量

#ifdef ENABLE_MANAGEMENT
    /* close management interface */
    close_management();
#endif

    /* uninitialize program-wide statics */
    uninit_static();

    openvpn_exit(OPENVPN_EXIT_STATUS_GOOD); /* exit point */
    return 0;                               /* NOTREACHED */
}

#ifdef _WIN32
int
wmain(int argc, wchar_t *wargv[])
{
    char **argv;
    int ret;
    int i;

    if ((argv = calloc(argc+1, sizeof(char *))) == NULL)
    {
        return 1;
    }

    for (i = 0; i < argc; i++)
    {
        int n = WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, NULL, 0, NULL, NULL);
        argv[i] = malloc(n);
        WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, argv[i], n, NULL, NULL);
    }

    ret = openvpn_main(argc, argv);

    for (i = 0; i < argc; i++)
    {
        free(argv[i]);
    }
    free(argv);

    return ret;
}
#else  /* ifdef _WIN32 */
int
main(int argc, char *argv[])
{
    return openvpn_main(argc, argv);
}
#endif /* ifdef _WIN32 */
