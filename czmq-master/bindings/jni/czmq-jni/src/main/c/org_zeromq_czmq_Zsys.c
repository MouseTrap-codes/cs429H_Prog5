/*
################################################################################
#  THIS FILE IS 100% GENERATED BY ZPROJECT; DO NOT EDIT EXCEPT EXPERIMENTALLY  #
#  Read the zproject/README.md for information about making permanent changes. #
################################################################################
*/
#include <stdio.h>
#include <stdlib.h>
#include <jni.h>
#include "czmq.h"
#include "org_zeromq_czmq_Zsys.h"

JNIEXPORT jlong JNICALL
Java_org_zeromq_czmq_Zsys__1_1init (JNIEnv *env, jclass c)
{
    jlong init_ = (jlong) (intptr_t) zsys_init ();
    return init_;
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1shutdown (JNIEnv *env, jclass c)
{
    zsys_shutdown ();
}

JNIEXPORT jlong JNICALL
Java_org_zeromq_czmq_Zsys__1_1socket (JNIEnv *env, jclass c, jint type, jstring filename, jlong line_nbr)
{
    char *filename_ = (char *) (*env)->GetStringUTFChars (env, filename, NULL);
    jlong socket_ = (jlong) (intptr_t) zsys_socket ((int) type, filename_, (size_t) line_nbr);
    (*env)->ReleaseStringUTFChars (env, filename, filename_);
    return socket_;
}

JNIEXPORT jint JNICALL
Java_org_zeromq_czmq_Zsys__1_1close (JNIEnv *env, jclass c, jlong handle, jstring filename, jlong line_nbr)
{
    char *filename_ = (char *) (*env)->GetStringUTFChars (env, filename, NULL);
    jint close_ = (jint) zsys_close ((void *) (intptr_t) handle, filename_, (size_t) line_nbr);
    (*env)->ReleaseStringUTFChars (env, filename, filename_);
    return close_;
}

JNIEXPORT jstring JNICALL
Java_org_zeromq_czmq_Zsys__1_1sockname (JNIEnv *env, jclass c, jint socktype)
{
    char *sockname_ = (char *) zsys_sockname ((int) socktype);
    jstring return_string_ = (*env)->NewStringUTF (env, sockname_);
    return return_string_;
}

JNIEXPORT jlong JNICALL
Java_org_zeromq_czmq_Zsys__1_1createPipe (JNIEnv *env, jclass c, jlong backend_p)
{
    jlong create_pipe_ = (jlong) (intptr_t) zsys_create_pipe ((zsock_t **) (intptr_t) &backend_p);
    return create_pipe_;
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1handlerReset (JNIEnv *env, jclass c)
{
    zsys_handler_reset ();
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1catchInterrupts (JNIEnv *env, jclass c)
{
    zsys_catch_interrupts ();
}

JNIEXPORT jboolean JNICALL
Java_org_zeromq_czmq_Zsys__1_1isInterrupted (JNIEnv *env, jclass c)
{
    jboolean is_interrupted_ = (jboolean) zsys_is_interrupted ();
    return is_interrupted_;
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1setInterrupted (JNIEnv *env, jclass c)
{
    zsys_set_interrupted ();
}

JNIEXPORT jboolean JNICALL
Java_org_zeromq_czmq_Zsys__1_1fileExists (JNIEnv *env, jclass c, jstring filename)
{
    char *filename_ = (char *) (*env)->GetStringUTFChars (env, filename, NULL);
    jboolean file_exists_ = (jboolean) zsys_file_exists (filename_);
    (*env)->ReleaseStringUTFChars (env, filename, filename_);
    return file_exists_;
}

JNIEXPORT jlong JNICALL
Java_org_zeromq_czmq_Zsys__1_1fileModified (JNIEnv *env, jclass c, jstring filename)
{
    char *filename_ = (char *) (*env)->GetStringUTFChars (env, filename, NULL);
    jlong file_modified_ = (jlong) zsys_file_modified (filename_);
    (*env)->ReleaseStringUTFChars (env, filename, filename_);
    return file_modified_;
}

JNIEXPORT jint JNICALL
Java_org_zeromq_czmq_Zsys__1_1fileMode (JNIEnv *env, jclass c, jstring filename)
{
    char *filename_ = (char *) (*env)->GetStringUTFChars (env, filename, NULL);
    jint file_mode_ = (jint) zsys_file_mode (filename_);
    (*env)->ReleaseStringUTFChars (env, filename, filename_);
    return file_mode_;
}

JNIEXPORT jint JNICALL
Java_org_zeromq_czmq_Zsys__1_1fileDelete (JNIEnv *env, jclass c, jstring filename)
{
    char *filename_ = (char *) (*env)->GetStringUTFChars (env, filename, NULL);
    jint file_delete_ = (jint) zsys_file_delete (filename_);
    (*env)->ReleaseStringUTFChars (env, filename, filename_);
    return file_delete_;
}

JNIEXPORT jboolean JNICALL
Java_org_zeromq_czmq_Zsys__1_1fileStable (JNIEnv *env, jclass c, jstring filename)
{
    char *filename_ = (char *) (*env)->GetStringUTFChars (env, filename, NULL);
    jboolean file_stable_ = (jboolean) zsys_file_stable (filename_);
    (*env)->ReleaseStringUTFChars (env, filename, filename_);
    return file_stable_;
}

JNIEXPORT jint JNICALL
Java_org_zeromq_czmq_Zsys__1_1dirCreate (JNIEnv *env, jclass c, jstring pathname)
{
    char *pathname_ = (char *) (*env)->GetStringUTFChars (env, pathname, NULL);
    jint dir_create_ = (jint) zsys_dir_create (pathname_, NULL);
    (*env)->ReleaseStringUTFChars (env, pathname, pathname_);
    return dir_create_;
}

JNIEXPORT jint JNICALL
Java_org_zeromq_czmq_Zsys__1_1dirDelete (JNIEnv *env, jclass c, jstring pathname)
{
    char *pathname_ = (char *) (*env)->GetStringUTFChars (env, pathname, NULL);
    jint dir_delete_ = (jint) zsys_dir_delete (pathname_, NULL);
    (*env)->ReleaseStringUTFChars (env, pathname, pathname_);
    return dir_delete_;
}

JNIEXPORT jint JNICALL
Java_org_zeromq_czmq_Zsys__1_1dirChange (JNIEnv *env, jclass c, jstring pathname)
{
    char *pathname_ = (char *) (*env)->GetStringUTFChars (env, pathname, NULL);
    jint dir_change_ = (jint) zsys_dir_change (pathname_);
    (*env)->ReleaseStringUTFChars (env, pathname, pathname_);
    return dir_change_;
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1fileModePrivate (JNIEnv *env, jclass c)
{
    zsys_file_mode_private ();
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1fileModeDefault (JNIEnv *env, jclass c)
{
    zsys_file_mode_default ();
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1version (JNIEnv *env, jclass c, jint major, jint minor, jint patch)
{
    zsys_version ((int *) (intptr_t) &major, (int *) (intptr_t) &minor, (int *) (intptr_t) &patch);
}

JNIEXPORT jstring JNICALL
Java_org_zeromq_czmq_Zsys__1_1sprintfHint (JNIEnv *env, jclass c, jint hint, jstring format)
{
    char *format_ = (char *) (*env)->GetStringUTFChars (env, format, NULL);
    char *sprintf_hint_ = (char *) zsys_sprintf_hint ((int) hint, format_);
    jstring return_string_ = (*env)->NewStringUTF (env, sprintf_hint_);
    (*env)->ReleaseStringUTFChars (env, format, format_);
    return return_string_;
}

JNIEXPORT jstring JNICALL
Java_org_zeromq_czmq_Zsys__1_1sprintf (JNIEnv *env, jclass c, jstring format)
{
    char *format_ = (char *) (*env)->GetStringUTFChars (env, format, NULL);
    char *sprintf_ = (char *) zsys_sprintf (format_);
    jstring return_string_ = (*env)->NewStringUTF (env, sprintf_);
    (*env)->ReleaseStringUTFChars (env, format, format_);
    return return_string_;
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1socketError (JNIEnv *env, jclass c, jstring reason)
{
    char *reason_ = (char *) (*env)->GetStringUTFChars (env, reason, NULL);
    zsys_socket_error (reason_);
    (*env)->ReleaseStringUTFChars (env, reason, reason_);
}

JNIEXPORT jstring JNICALL
Java_org_zeromq_czmq_Zsys__1_1hostname (JNIEnv *env, jclass c)
{
    char *hostname_ = (char *) zsys_hostname ();
    jstring return_string_ = (*env)->NewStringUTF (env, hostname_);
    return return_string_;
}

JNIEXPORT jint JNICALL
Java_org_zeromq_czmq_Zsys__1_1daemonize (JNIEnv *env, jclass c, jstring workdir)
{
    char *workdir_ = (char *) (*env)->GetStringUTFChars (env, workdir, NULL);
    jint daemonize_ = (jint) zsys_daemonize (workdir_);
    (*env)->ReleaseStringUTFChars (env, workdir, workdir_);
    return daemonize_;
}

JNIEXPORT jint JNICALL
Java_org_zeromq_czmq_Zsys__1_1runAs (JNIEnv *env, jclass c, jstring lockfile, jstring group, jstring user)
{
    char *lockfile_ = (char *) (*env)->GetStringUTFChars (env, lockfile, NULL);
    char *group_ = (char *) (*env)->GetStringUTFChars (env, group, NULL);
    char *user_ = (char *) (*env)->GetStringUTFChars (env, user, NULL);
    jint run_as_ = (jint) zsys_run_as (lockfile_, group_, user_);
    (*env)->ReleaseStringUTFChars (env, lockfile, lockfile_);
    (*env)->ReleaseStringUTFChars (env, group, group_);
    (*env)->ReleaseStringUTFChars (env, user, user_);
    return run_as_;
}

JNIEXPORT jboolean JNICALL
Java_org_zeromq_czmq_Zsys__1_1hasCurve (JNIEnv *env, jclass c)
{
    jboolean has_curve_ = (jboolean) zsys_has_curve ();
    return has_curve_;
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1setIoThreads (JNIEnv *env, jclass c, jlong io_threads)
{
    zsys_set_io_threads ((size_t) io_threads);
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1setThreadSchedPolicy (JNIEnv *env, jclass c, jint policy)
{
    zsys_set_thread_sched_policy ((int) policy);
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1setThreadPriority (JNIEnv *env, jclass c, jint priority)
{
    zsys_set_thread_priority ((int) priority);
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1setThreadNamePrefix (JNIEnv *env, jclass c, jint prefix)
{
    zsys_set_thread_name_prefix ((int) prefix);
}

JNIEXPORT jint JNICALL
Java_org_zeromq_czmq_Zsys__1_1threadNamePrefix (JNIEnv *env, jclass c)
{
    jint thread_name_prefix_ = (jint) zsys_thread_name_prefix ();
    return thread_name_prefix_;
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1setThreadNamePrefixStr (JNIEnv *env, jclass c, jstring prefix)
{
    char *prefix_ = (char *) (*env)->GetStringUTFChars (env, prefix, NULL);
    zsys_set_thread_name_prefix_str (prefix_);
    (*env)->ReleaseStringUTFChars (env, prefix, prefix_);
}

JNIEXPORT jstring JNICALL
Java_org_zeromq_czmq_Zsys__1_1threadNamePrefixStr (JNIEnv *env, jclass c)
{
    char *thread_name_prefix_str_ = (char *) zsys_thread_name_prefix_str ();
    jstring return_string_ = (*env)->NewStringUTF (env, thread_name_prefix_str_);
    return return_string_;
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1threadAffinityCpuAdd (JNIEnv *env, jclass c, jint cpu)
{
    zsys_thread_affinity_cpu_add ((int) cpu);
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1threadAffinityCpuRemove (JNIEnv *env, jclass c, jint cpu)
{
    zsys_thread_affinity_cpu_remove ((int) cpu);
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1setMaxSockets (JNIEnv *env, jclass c, jlong max_sockets)
{
    zsys_set_max_sockets ((size_t) max_sockets);
}

JNIEXPORT jlong JNICALL
Java_org_zeromq_czmq_Zsys__1_1socketLimit (JNIEnv *env, jclass c)
{
    jlong socket_limit_ = (jlong) zsys_socket_limit ();
    return socket_limit_;
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1setMaxMsgsz (JNIEnv *env, jclass c, jint max_msgsz)
{
    zsys_set_max_msgsz ((int) max_msgsz);
}

JNIEXPORT jint JNICALL
Java_org_zeromq_czmq_Zsys__1_1maxMsgsz (JNIEnv *env, jclass c)
{
    jint max_msgsz_ = (jint) zsys_max_msgsz ();
    return max_msgsz_;
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1setZeroCopyRecv (JNIEnv *env, jclass c, jint zero_copy)
{
    zsys_set_zero_copy_recv ((int) zero_copy);
}

JNIEXPORT jint JNICALL
Java_org_zeromq_czmq_Zsys__1_1zeroCopyRecv (JNIEnv *env, jclass c)
{
    jint zero_copy_recv_ = (jint) zsys_zero_copy_recv ();
    return zero_copy_recv_;
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1setFileStableAgeMsec (JNIEnv *env, jclass c, jlong file_stable_age_msec)
{
    zsys_set_file_stable_age_msec ((int64_t) file_stable_age_msec);
}

JNIEXPORT jlong JNICALL
Java_org_zeromq_czmq_Zsys__1_1fileStableAgeMsec (JNIEnv *env, jclass c)
{
    jlong file_stable_age_msec_ = (jlong) zsys_file_stable_age_msec ();
    return file_stable_age_msec_;
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1setLinger (JNIEnv *env, jclass c, jlong linger)
{
    zsys_set_linger ((size_t) linger);
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1setSndhwm (JNIEnv *env, jclass c, jlong sndhwm)
{
    zsys_set_sndhwm ((size_t) sndhwm);
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1setRcvhwm (JNIEnv *env, jclass c, jlong rcvhwm)
{
    zsys_set_rcvhwm ((size_t) rcvhwm);
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1setPipehwm (JNIEnv *env, jclass c, jlong pipehwm)
{
    zsys_set_pipehwm ((size_t) pipehwm);
}

JNIEXPORT jlong JNICALL
Java_org_zeromq_czmq_Zsys__1_1pipehwm (JNIEnv *env, jclass c)
{
    jlong pipehwm_ = (jlong) zsys_pipehwm ();
    return pipehwm_;
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1setIpv6 (JNIEnv *env, jclass c, jint ipv6)
{
    zsys_set_ipv6 ((int) ipv6);
}

JNIEXPORT jint JNICALL
Java_org_zeromq_czmq_Zsys__1_1ipv6 (JNIEnv *env, jclass c)
{
    jint ipv6_ = (jint) zsys_ipv6 ();
    return ipv6_;
}

JNIEXPORT jboolean JNICALL
Java_org_zeromq_czmq_Zsys__1_1ipv6Available (JNIEnv *env, jclass c)
{
    jboolean ipv6_available_ = (jboolean) zsys_ipv6_available ();
    return ipv6_available_;
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1setInterface (JNIEnv *env, jclass c, jstring value)
{
    char *value_ = (char *) (*env)->GetStringUTFChars (env, value, NULL);
    zsys_set_interface (value_);
    (*env)->ReleaseStringUTFChars (env, value, value_);
}

JNIEXPORT jstring JNICALL
Java_org_zeromq_czmq_Zsys__1_1interface (JNIEnv *env, jclass c)
{
    char *interface_ = (char *) zsys_interface ();
    jstring return_string_ = (*env)->NewStringUTF (env, interface_);
    return return_string_;
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1setIpv6Address (JNIEnv *env, jclass c, jstring value)
{
    char *value_ = (char *) (*env)->GetStringUTFChars (env, value, NULL);
    zsys_set_ipv6_address (value_);
    (*env)->ReleaseStringUTFChars (env, value, value_);
}

JNIEXPORT jstring JNICALL
Java_org_zeromq_czmq_Zsys__1_1ipv6Address (JNIEnv *env, jclass c)
{
    char *ipv6_address_ = (char *) zsys_ipv6_address ();
    jstring return_string_ = (*env)->NewStringUTF (env, ipv6_address_);
    return return_string_;
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1setIpv6McastAddress (JNIEnv *env, jclass c, jstring value)
{
    char *value_ = (char *) (*env)->GetStringUTFChars (env, value, NULL);
    zsys_set_ipv6_mcast_address (value_);
    (*env)->ReleaseStringUTFChars (env, value, value_);
}

JNIEXPORT jstring JNICALL
Java_org_zeromq_czmq_Zsys__1_1ipv6McastAddress (JNIEnv *env, jclass c)
{
    char *ipv6_mcast_address_ = (char *) zsys_ipv6_mcast_address ();
    jstring return_string_ = (*env)->NewStringUTF (env, ipv6_mcast_address_);
    return return_string_;
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1setIpv4McastAddress (JNIEnv *env, jclass c, jstring value)
{
    char *value_ = (char *) (*env)->GetStringUTFChars (env, value, NULL);
    zsys_set_ipv4_mcast_address (value_);
    (*env)->ReleaseStringUTFChars (env, value, value_);
}

JNIEXPORT jstring JNICALL
Java_org_zeromq_czmq_Zsys__1_1ipv4McastAddress (JNIEnv *env, jclass c)
{
    char *ipv4_mcast_address_ = (char *) zsys_ipv4_mcast_address ();
    jstring return_string_ = (*env)->NewStringUTF (env, ipv4_mcast_address_);
    return return_string_;
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1setMcastTtl (JNIEnv *env, jclass c, jbyte value)
{
    zsys_set_mcast_ttl ((byte) value);
}

JNIEXPORT jbyte JNICALL
Java_org_zeromq_czmq_Zsys__1_1mcastTtl (JNIEnv *env, jclass c)
{
    jbyte mcast_ttl_ = (jbyte) zsys_mcast_ttl ();
    return mcast_ttl_;
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1setAutoUseFd (JNIEnv *env, jclass c, jint auto_use_fd)
{
    zsys_set_auto_use_fd ((int) auto_use_fd);
}

JNIEXPORT jint JNICALL
Java_org_zeromq_czmq_Zsys__1_1autoUseFd (JNIEnv *env, jclass c)
{
    jint auto_use_fd_ = (jint) zsys_auto_use_fd ();
    return auto_use_fd_;
}

JNIEXPORT jstring JNICALL
Java_org_zeromq_czmq_Zsys__1_1zprintf (JNIEnv *env, jclass c, jstring format, jlong args)
{
    char *format_ = (char *) (*env)->GetStringUTFChars (env, format, NULL);
    char *zprintf_ = (char *) zsys_zprintf (format_, (zhash_t *) (intptr_t) args);
    jstring return_string_ = (*env)->NewStringUTF (env, zprintf_);
    zstr_free (&zprintf_);
    (*env)->ReleaseStringUTFChars (env, format, format_);
    return return_string_;
}

JNIEXPORT jstring JNICALL
Java_org_zeromq_czmq_Zsys__1_1zprintfError (JNIEnv *env, jclass c, jstring format, jlong args)
{
    char *format_ = (char *) (*env)->GetStringUTFChars (env, format, NULL);
    char *zprintf_error_ = (char *) zsys_zprintf_error (format_, (zhash_t *) (intptr_t) args);
    jstring return_string_ = (*env)->NewStringUTF (env, zprintf_error_);
    zstr_free (&zprintf_error_);
    (*env)->ReleaseStringUTFChars (env, format, format_);
    return return_string_;
}

JNIEXPORT jstring JNICALL
Java_org_zeromq_czmq_Zsys__1_1zplprintf (JNIEnv *env, jclass c, jstring format, jlong args)
{
    char *format_ = (char *) (*env)->GetStringUTFChars (env, format, NULL);
    char *zplprintf_ = (char *) zsys_zplprintf (format_, (zconfig_t *) (intptr_t) args);
    jstring return_string_ = (*env)->NewStringUTF (env, zplprintf_);
    zstr_free (&zplprintf_);
    (*env)->ReleaseStringUTFChars (env, format, format_);
    return return_string_;
}

JNIEXPORT jstring JNICALL
Java_org_zeromq_czmq_Zsys__1_1zplprintfError (JNIEnv *env, jclass c, jstring format, jlong args)
{
    char *format_ = (char *) (*env)->GetStringUTFChars (env, format, NULL);
    char *zplprintf_error_ = (char *) zsys_zplprintf_error (format_, (zconfig_t *) (intptr_t) args);
    jstring return_string_ = (*env)->NewStringUTF (env, zplprintf_error_);
    zstr_free (&zplprintf_error_);
    (*env)->ReleaseStringUTFChars (env, format, format_);
    return return_string_;
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1setLogident (JNIEnv *env, jclass c, jstring value)
{
    char *value_ = (char *) (*env)->GetStringUTFChars (env, value, NULL);
    zsys_set_logident (value_);
    (*env)->ReleaseStringUTFChars (env, value, value_);
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1setLogsender (JNIEnv *env, jclass c, jstring endpoint)
{
    char *endpoint_ = (char *) (*env)->GetStringUTFChars (env, endpoint, NULL);
    zsys_set_logsender (endpoint_);
    (*env)->ReleaseStringUTFChars (env, endpoint, endpoint_);
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1setLogsystem (JNIEnv *env, jclass c, jboolean logsystem)
{
    zsys_set_logsystem ((bool) logsystem);
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1error (JNIEnv *env, jclass c, jstring format)
{
    char *format_ = (char *) (*env)->GetStringUTFChars (env, format, NULL);
    zsys_error (format_);
    (*env)->ReleaseStringUTFChars (env, format, format_);
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1warning (JNIEnv *env, jclass c, jstring format)
{
    char *format_ = (char *) (*env)->GetStringUTFChars (env, format, NULL);
    zsys_warning (format_);
    (*env)->ReleaseStringUTFChars (env, format, format_);
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1notice (JNIEnv *env, jclass c, jstring format)
{
    char *format_ = (char *) (*env)->GetStringUTFChars (env, format, NULL);
    zsys_notice (format_);
    (*env)->ReleaseStringUTFChars (env, format, format_);
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1info (JNIEnv *env, jclass c, jstring format)
{
    char *format_ = (char *) (*env)->GetStringUTFChars (env, format, NULL);
    zsys_info (format_);
    (*env)->ReleaseStringUTFChars (env, format, format_);
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1debug (JNIEnv *env, jclass c, jstring format)
{
    char *format_ = (char *) (*env)->GetStringUTFChars (env, format, NULL);
    zsys_debug (format_);
    (*env)->ReleaseStringUTFChars (env, format, format_);
}

JNIEXPORT void JNICALL
Java_org_zeromq_czmq_Zsys__1_1test (JNIEnv *env, jclass c, jboolean verbose)
{
    zsys_test ((bool) verbose);
}

