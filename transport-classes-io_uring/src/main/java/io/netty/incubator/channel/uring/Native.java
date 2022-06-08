/*
 * Copyright 2020 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.netty.incubator.channel.uring;

import io.netty.channel.unix.FileDescriptor;
import io.netty.channel.unix.PeerCredentials;
import io.netty.channel.unix.Unix;
import io.netty.util.internal.ClassInitializerUtil;
import io.netty.util.internal.NativeLibraryLoader;
import io.netty.util.internal.PlatformDependent;
import io.netty.util.internal.SystemPropertyUtil;
import io.netty.util.internal.ThrowableUtil;
import io.netty.util.internal.logging.InternalLogger;
import io.netty.util.internal.logging.InternalLoggerFactory;

import java.io.File;
import java.io.IOException;
import java.nio.channels.Selector;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.Locale;

public final class Native {
    private static final InternalLogger logger = InternalLoggerFactory.getInstance(Native.class);
    public static final int DEFAULT_RING_SIZE = Math.max(64, SystemPropertyUtil.getInt("io.netty.iouring.ringSize", 4096));
    public static final int DEFAULT_IOSEQ_ASYNC_THRESHOLD =
            Math.max(0, SystemPropertyUtil.getInt("io.netty.iouring.iosqeAsyncThreshold", 25));

    static {
        Selector selector = null;
        try {
            // We call Selector.open() as this will under the hood cause IOUtil to be loaded.
            // This is a workaround for a possible classloader deadlock that could happen otherwise:
            //
            // See https://github.com/netty/netty/issues/10187
            selector = Selector.open();
        } catch (IOException ignore) {
            // Just ignore
        }

        // Preload all classes that will be used in the OnLoad(...) function of JNI to eliminate the possiblity of a
        // class-loader deadlock. This is a workaround for https://github.com/netty/netty/issues/11209.

        // This needs to match all the classes that are loaded via NETTY_JNI_UTIL_LOAD_CLASS or looked up via
        // NETTY_JNI_UTIL_FIND_CLASS.
        ClassInitializerUtil.tryLoadClasses(Native.class,
                // netty_io_uring_linuxsocket
                PeerCredentials.class, java.io.FileDescriptor.class
        );

        File tmpDir = PlatformDependent.tmpdir();
        Path tmpFile = tmpDir.toPath().resolve("netty_io_uring.tmp");
        try {
            // First, try calling a side-effect free JNI method to see if the library was already
            // loaded by the application.
            Native.createFile(tmpFile.toString());
        } catch (UnsatisfiedLinkError ignore) {
            // The library was not previously loaded, load it now.
            loadNativeLibrary();
        } finally {
            tmpFile.toFile().delete();
            try {
                if (selector != null) {
                    selector.close();
                }
            } catch (IOException ignore) {
                // Just ignore
            }
        }
        Unix.registerInternal(new Runnable() {
            @Override
            public void run() {
                registerUnix();
            }
        });
    }
    public static final int SOCK_NONBLOCK = NativeStaticallyReferencedJniMethods.sockNonblock();
    public static final int SOCK_CLOEXEC = NativeStaticallyReferencedJniMethods.sockCloexec();
    public static final short AF_INET = (short) NativeStaticallyReferencedJniMethods.afInet();
    public static final short AF_INET6 = (short) NativeStaticallyReferencedJniMethods.afInet6();
    public static final int SIZEOF_SOCKADDR_STORAGE = NativeStaticallyReferencedJniMethods.sizeofSockaddrStorage();
    public static final int SIZEOF_SOCKADDR_IN = NativeStaticallyReferencedJniMethods.sizeofSockaddrIn();
    public static final int SIZEOF_SOCKADDR_IN6 = NativeStaticallyReferencedJniMethods.sizeofSockaddrIn6();
    public static final int SOCKADDR_IN_OFFSETOF_SIN_FAMILY =
            NativeStaticallyReferencedJniMethods.sockaddrInOffsetofSinFamily();
    public static final int SOCKADDR_IN_OFFSETOF_SIN_PORT = NativeStaticallyReferencedJniMethods.sockaddrInOffsetofSinPort();
    public static final int SOCKADDR_IN_OFFSETOF_SIN_ADDR = NativeStaticallyReferencedJniMethods.sockaddrInOffsetofSinAddr();
    public static final int IN_ADDRESS_OFFSETOF_S_ADDR = NativeStaticallyReferencedJniMethods.inAddressOffsetofSAddr();
    public static final int SOCKADDR_IN6_OFFSETOF_SIN6_FAMILY =
            NativeStaticallyReferencedJniMethods.sockaddrIn6OffsetofSin6Family();
    public static final int SOCKADDR_IN6_OFFSETOF_SIN6_PORT =
            NativeStaticallyReferencedJniMethods.sockaddrIn6OffsetofSin6Port();
    public static final int SOCKADDR_IN6_OFFSETOF_SIN6_FLOWINFO =
            NativeStaticallyReferencedJniMethods.sockaddrIn6OffsetofSin6Flowinfo();
    public static final int SOCKADDR_IN6_OFFSETOF_SIN6_ADDR =
            NativeStaticallyReferencedJniMethods.sockaddrIn6OffsetofSin6Addr();
    public static final int SOCKADDR_IN6_OFFSETOF_SIN6_SCOPE_ID =
            NativeStaticallyReferencedJniMethods.sockaddrIn6OffsetofSin6ScopeId();
    public static final int IN6_ADDRESS_OFFSETOF_S6_ADDR = NativeStaticallyReferencedJniMethods.in6AddressOffsetofS6Addr();
    public static final int SIZEOF_SIZE_T = NativeStaticallyReferencedJniMethods.sizeofSizeT();
    public static final int SIZEOF_IOVEC = NativeStaticallyReferencedJniMethods.sizeofIovec();
    public static final int CMSG_SPACE = NativeStaticallyReferencedJniMethods.cmsgSpace();
    public static final int CMSG_LEN = NativeStaticallyReferencedJniMethods.cmsgLen();
    public static final int CMSG_OFFSETOF_CMSG_LEN = NativeStaticallyReferencedJniMethods.cmsghdrOffsetofCmsgLen();
    public static final int CMSG_OFFSETOF_CMSG_LEVEL = NativeStaticallyReferencedJniMethods.cmsghdrOffsetofCmsgLevel();
    public static final int CMSG_OFFSETOF_CMSG_TYPE = NativeStaticallyReferencedJniMethods.cmsghdrOffsetofCmsgType();

    public static final int IOVEC_OFFSETOF_IOV_BASE = NativeStaticallyReferencedJniMethods.iovecOffsetofIovBase();
    public static final int IOVEC_OFFSETOF_IOV_LEN = NativeStaticallyReferencedJniMethods.iovecOffsetofIovLen();
    public static final int SIZEOF_MSGHDR = NativeStaticallyReferencedJniMethods.sizeofMsghdr();
    public static final int MSGHDR_OFFSETOF_MSG_NAME = NativeStaticallyReferencedJniMethods.msghdrOffsetofMsgName();
    public static final int MSGHDR_OFFSETOF_MSG_NAMELEN = NativeStaticallyReferencedJniMethods.msghdrOffsetofMsgNamelen();
    public static final int MSGHDR_OFFSETOF_MSG_IOV = NativeStaticallyReferencedJniMethods.msghdrOffsetofMsgIov();
    public static final int MSGHDR_OFFSETOF_MSG_IOVLEN = NativeStaticallyReferencedJniMethods.msghdrOffsetofMsgIovlen();
    public static final int MSGHDR_OFFSETOF_MSG_CONTROL = NativeStaticallyReferencedJniMethods.msghdrOffsetofMsgControl();
    public static final int MSGHDR_OFFSETOF_MSG_CONTROLLEN =
            NativeStaticallyReferencedJniMethods.msghdrOffsetofMsgControllen();
    public static final int MSGHDR_OFFSETOF_MSG_FLAGS = NativeStaticallyReferencedJniMethods.msghdrOffsetofMsgFlags();
    public static final int POLLIN = NativeStaticallyReferencedJniMethods.pollin();
    public static final int POLLOUT = NativeStaticallyReferencedJniMethods.pollout();
    public static final int POLLRDHUP = NativeStaticallyReferencedJniMethods.pollrdhup();
    public static final int ERRNO_ECANCELED_NEGATIVE = -NativeStaticallyReferencedJniMethods.ecanceled();
    public static final int ERRNO_ETIME_NEGATIVE = -NativeStaticallyReferencedJniMethods.etime();
    public static final byte IORING_OP_POLL_ADD = NativeStaticallyReferencedJniMethods.ioringOpPollAdd();
    public static final byte IORING_OP_TIMEOUT = NativeStaticallyReferencedJniMethods.ioringOpTimeout();
    public static final byte IORING_OP_ACCEPT = NativeStaticallyReferencedJniMethods.ioringOpAccept();
    public static final byte IORING_OP_READ = NativeStaticallyReferencedJniMethods.ioringOpRead();
    public static final byte IORING_OP_WRITE = NativeStaticallyReferencedJniMethods.ioringOpWrite();
    public static final byte IORING_OP_POLL_REMOVE = NativeStaticallyReferencedJniMethods.ioringOpPollRemove();
    public static final byte IORING_OP_CONNECT = NativeStaticallyReferencedJniMethods.ioringOpConnect();
    public static final byte IORING_OP_CLOSE = NativeStaticallyReferencedJniMethods.ioringOpClose();
    public static final byte IORING_OP_WRITEV = NativeStaticallyReferencedJniMethods.ioringOpWritev();
    public static final byte IORING_OP_SENDMSG = NativeStaticallyReferencedJniMethods.ioringOpSendmsg();
    public static final byte IORING_OP_RECVMSG = NativeStaticallyReferencedJniMethods.ioringOpRecvmsg();
    public static final byte IORING_OP_FSYNC = NativeStaticallyReferencedJniMethods.ioringOpFsync();
    public static final int IORING_ENTER_GETEVENTS = NativeStaticallyReferencedJniMethods.ioringEnterGetevents();
    public static final int IOSQE_ASYNC = NativeStaticallyReferencedJniMethods.iosqeAsync();
    public static final int MSG_DONTWAIT = NativeStaticallyReferencedJniMethods.msgDontwait();
    public static final int SOL_UDP = NativeStaticallyReferencedJniMethods.solUdp();
    public static final int UDP_SEGMENT = NativeStaticallyReferencedJniMethods.udpSegment();

    private static final int[] REQUIRED_IORING_OPS = {
            IORING_OP_POLL_ADD,
            IORING_OP_TIMEOUT,
            IORING_OP_ACCEPT,
            IORING_OP_READ,
            IORING_OP_WRITE,
            IORING_OP_POLL_REMOVE,
            IORING_OP_CONNECT,
            IORING_OP_CLOSE,
            IORING_OP_WRITEV,
            IORING_OP_SENDMSG,
            IORING_OP_RECVMSG
    };

    public static RingBuffer createRingBuffer(int ringSize) {
        return createRingBuffer(ringSize, DEFAULT_IOSEQ_ASYNC_THRESHOLD);
    }

    public static RingBuffer createRingBuffer(int ringSize, int iosqeAsyncThreshold) {
        return createRingBuffer(ringSize,iosqeAsyncThreshold,0);
    }

    public static RingBuffer createRingBuffer(int ringSize, int iosqeAsyncThreshold, int flags) {
        long[][] values = ioUringSetup(ringSize, flags);
        assert values.length == 2;
        long[] submissionQueueArgs = values[0];
        assert submissionQueueArgs.length == 11;
        IOUringSubmissionQueue submissionQueue = new IOUringSubmissionQueue(
                submissionQueueArgs[0],
                submissionQueueArgs[1],
                submissionQueueArgs[2],
                submissionQueueArgs[3],
                submissionQueueArgs[4],
                submissionQueueArgs[5],
                submissionQueueArgs[6],
                submissionQueueArgs[7],
                (int) submissionQueueArgs[8],
                submissionQueueArgs[9],
                (int) submissionQueueArgs[10],
                iosqeAsyncThreshold);
        long[] completionQueueArgs = values[1];
        assert completionQueueArgs.length == 9;
        IOUringCompletionQueue completionQueue = new IOUringCompletionQueue(
                completionQueueArgs[0],
                completionQueueArgs[1],
                completionQueueArgs[2],
                completionQueueArgs[3],
                completionQueueArgs[4],
                completionQueueArgs[5],
                (int) completionQueueArgs[6],
                completionQueueArgs[7],
                (int) completionQueueArgs[8]);
        return new RingBuffer(submissionQueue, completionQueue);
    }

    public static RingBuffer createRingBuffer() {
        return createRingBuffer(DEFAULT_RING_SIZE, DEFAULT_IOSEQ_ASYNC_THRESHOLD);
    }

    public static void checkAllIOSupported(int ringFd) {
        if (!ioUringProbe(ringFd, REQUIRED_IORING_OPS)) {
            throw new UnsupportedOperationException("Not all operations are supported: "
                    + Arrays.toString(REQUIRED_IORING_OPS));
        }
    }

    public static void checkKernelVersion(String kernelVersion) {
        boolean enforceKernelVersion = SystemPropertyUtil.getBoolean(
                "io.netty.transport.iouring.enforceKernelVersion", true);
        boolean kernelSupported = checkKernelVersion0(kernelVersion);
        if (!kernelSupported) {
            if (enforceKernelVersion) {
                throw new UnsupportedOperationException(
                        "you need at least kernel version 5.9, current kernel version: " + kernelVersion);
            } else {
                logger.debug("Detected kernel " + kernelVersion + " does not match minimum version of 5.9, " +
                        "trying to use io_uring anyway");
            }
        }
    }

    private static boolean checkKernelVersion0(String kernelVersion) {
        String[] versionComponents = kernelVersion.split("\\.");
        if (versionComponents.length < 3) {
            return false;
        }

        int major;
        try {
            major = Integer.parseInt(versionComponents[0]);
        } catch (NumberFormatException e) {
            return false;
        }

        if (major <= 4) {
            return false;
        }
        if (major > 5) {
            return true;
        }

        int minor;
        try {
            minor = Integer.parseInt(versionComponents[1]);
        } catch (NumberFormatException e) {
            return false;
        }

        return minor >= 9;
    }

    private static native boolean ioUringProbe(int ringFd, int[] ios);
    private static native long[][] ioUringSetup(int entries, int flags);

    public static native int ioUringEnter(int ringFd, int toSubmit, int minComplete, int flags);

    public static native void eventFdWrite(int fd, long value);

    public static FileDescriptor newBlockingEventFd() {
        return new FileDescriptor(blockingEventFd());
    }

    public static native void ioUringExit(long submissionQueueArrayAddress, int submissionQueueRingEntries,
                                          long submissionQueueRingAddress, int submissionQueueRingSize,
                                          long completionQueueRingAddress, int completionQueueRingSize,
                                          int ringFd);

    private static native int blockingEventFd();

    // for testing only!
    static native int createFile(String name);

    private static native int registerUnix();

    public static native long cmsghdrData(long hdrAddr);

    public static native String kernelVersion();

    private Native() {
        // utility
    }

    // From io_uring native library
    private static void loadNativeLibrary() {
        String name = PlatformDependent.normalizedOs().toLowerCase(Locale.UK).trim();
        if (!name.startsWith("linux")) {
            throw new IllegalStateException("Only supported on Linux");
        }
        String staticLibName = "netty_transport_native_io_uring";
        String sharedLibName = staticLibName + '_' + PlatformDependent.normalizedArch();
        ClassLoader cl = PlatformDependent.getClassLoader(Native.class);
        try {
            NativeLibraryLoader.load(sharedLibName, cl);
        } catch (UnsatisfiedLinkError e1) {
            try {
                NativeLibraryLoader.load(staticLibName, cl);
                logger.info("Failed to load io_uring");
            } catch (UnsatisfiedLinkError e2) {
                ThrowableUtil.addSuppressed(e1, e2);
                throw e1;
            }
        }
    }
}
