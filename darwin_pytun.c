#define PY_SSIZE_T_CLEAN

#include <Python.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <stdio.h>
#include <sys/kern_event.h>
#include <sys/kern_control.h>

#include "common.h"

#define KERN_SUCCESS (0)
#define UTUN_CONTROL_NAME "com.apple.net.utun_control"
#define UTUN_OPT_IFNAME (2)

#ifndef PyVarObject_HEAD_INIT
#define PyVarObject_HEAD_INIT(type, size) \
    PyObject_HEAD_INIT(type) size,
#endif

static PyObject *pytun_error = NULL;

PyDoc_STRVAR(pytun_error_doc,
             "This exception is raised when an error occurs. The accompanying value is\n\
either a string telling what went wrong or a pair (errno, string)\n\
representing an error returned by a system call, similar to the value\n\
accompanying os.error. See the module errno, which contains names for the\n\
error codes defined by the underlying operating system.");

static void raise_error(const char *errmsg) {
    PyErr_SetString(pytun_error, errmsg);
}

static void raise_error_from_errno(void) {
    PyErr_SetFromErrno(pytun_error);
}

static int create_utun_interface(u_int32_t num, size_t ifname_len, char *ifname) {
    struct sockaddr_ctl addr;
    struct ctl_info info;

    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);

    bzero(&info, sizeof(info));
    strncpy(info.ctl_name, UTUN_CONTROL_NAME, MAX_KCTL_NAME);
    if (ioctl(fd, CTLIOCGINFO, &info) != KERN_SUCCESS) {
        close(fd);
        return -1;
    }

    addr.sc_id = info.ctl_id;
    addr.sc_len = sizeof(addr);
    addr.sc_family = AF_SYSTEM;
    addr.ss_sysaddr = AF_SYS_CONTROL;
    addr.sc_unit = num + 1; // utunX where X is sc.sc_unit -1
    if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) != KERN_SUCCESS) {
        close(fd);
        return -1;
    }

    if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, (socklen_t *) &ifname_len) != KERN_SUCCESS) {
        close(fd);
        return -1;
    }

    return fd;
}

static PyObject *pytun_tuntap_new(PyTypeObject *type, PyObject *args, PyObject *kwds) {
    pytun_tuntap_t *tuntap = (pytun_tuntap_t *) type->tp_alloc(type, 0);
    int i = 0;
    int fd;

    char name[sizeof(tuntap->name)];
    while (-1 == (fd = create_utun_interface(i, sizeof(name), name))) {
        ++i;
    }
    if (-1 == fd) {
        raise_error("Failed to create tun device");
    }
    tuntap->fd = fd;
    strcpy(tuntap->name, name);
    return (PyObject *) tuntap;
}

static void pytun_tuntap_dealloc(PyObject *self) {
    pytun_tuntap_t *tuntap = (pytun_tuntap_t *) self;

    if (tuntap->fd >= 0) {
        Py_BEGIN_ALLOW_THREADS
            close(tuntap->fd);
        Py_END_ALLOW_THREADS
    }
    self->ob_type->tp_free(self);
}

static PyObject *pytun_tuntap_get_name(PyObject *self, void *d) {
    pytun_tuntap_t *tuntap = (pytun_tuntap_t *) self;

#if PY_MAJOR_VERSION >= 3
    return PyUnicode_FromString(tuntap->name);
#else
    return PyString_FromString(tuntap->name);
#endif
}

static int pytun_tuntap_set_addr6(PyObject *self, PyObject *value, void *d) {
    pytun_tuntap_t *tuntap = (pytun_tuntap_t *) self;
    int ret = 0;
    char cmd[1024];

#if PY_MAJOR_VERSION >= 3
    PyObject *tmp_addr;
#endif
    const char *addr;

#if PY_MAJOR_VERSION >= 3
    tmp_addr = PyUnicode_AsASCIIString(value);
    addr = tmp_addr != NULL ? PyBytes_AS_STRING(tmp_addr) : NULL;
#else
    addr = PyString_AsString(value);
#endif
    if (addr == NULL) {
        ret = -1;
        goto out;
    }

    sprintf(cmd, "ifconfig %s inet6 %s prefixlen 64", tuntap->name, addr);
    if (system(cmd) != 0) {
        ret = -1;
        goto out;
    }

    out:
#if PY_MAJOR_VERSION >= 3
    Py_XDECREF(tmp_addr);
#endif

    return ret;
}

static PyObject *pytun_tuntap_get_mtu(PyObject *self, void *d) {
    pytun_tuntap_t *tuntap = (pytun_tuntap_t *) self;
    struct ifreq req;
    int ret;

    memset(&req, 0, sizeof(req));
    strcpy(req.ifr_name, tuntap->name);

    Py_BEGIN_ALLOW_THREADS;
        ret = ioctl(tuntap->fd, SIOCGIFMTU, &req);
    Py_END_ALLOW_THREADS;
    if (ret < 0) {
        raise_error_from_errno();
        return NULL;
    }

#if PY_MAJOR_VERSION >= 3
    return PyLong_FromLong(req.ifr_mtu);
#else
    return PyInt_FromLong(req.ifr_mtu);
#endif
}

static int pytun_tuntap_set_mtu(PyObject *self, PyObject *value, void *d) {
    pytun_tuntap_t *tuntap = (pytun_tuntap_t *) self;
    struct ifreq req;
    int mtu;
    int err;

    mtu = (int) PyLong_AsLong(value);
    if (mtu <= 0) {
        if (!PyErr_Occurred()) {
            raise_error("Bad MTU, should be > 0");
        }
        return -1;
    }
    memset(&req, 0, sizeof(req));
    strcpy(req.ifr_name, tuntap->name);
    req.ifr_mtu = mtu;

    Py_BEGIN_ALLOW_THREADS;
        err = ioctl(tuntap->fd, SIOCSIFMTU, &req);
    Py_END_ALLOW_THREADS;
    if (err < 0) {
        raise_error_from_errno();
        return -1;
    }

    return 0;
}

static PyGetSetDef pytun_tuntap_prop[] =
        {
                {
                        "name",
                        pytun_tuntap_get_name,
                              NULL,
                                    NULL,
                                          NULL
                },
                {
                        "addr",
                        NULL,
                              NULL,
                                    NULL,
                                          NULL
                },
                {
                        "addr6",
                        NULL,
                        pytun_tuntap_set_addr6,
                                    NULL,
                                          NULL
                },
                {
                        "dstaddr",
                        NULL,
                              NULL,
                                    NULL, NULL
                },
                {
                        "hwaddr",
                        NULL,
                              NULL,
                                    NULL,
                                          NULL
                },
                {
                        "netmask",
                        NULL,
                              NULL,
                                    NULL,
                                          NULL
                },
                {
                        "mtu",
                        pytun_tuntap_get_mtu,
                        pytun_tuntap_set_mtu,
                                    NULL,
                                          NULL
                },
                {NULL,  NULL, NULL, NULL, NULL}
        };

static PyObject *pytun_tuntap_close(PyObject *self) {
    pytun_tuntap_t *tuntap = (pytun_tuntap_t *) self;

    if (tuntap->fd >= 0) {
        Py_BEGIN_ALLOW_THREADS
            close(tuntap->fd), tuntap->fd = -1;
        Py_END_ALLOW_THREADS
    }

    Py_RETURN_NONE;
}

PyDoc_STRVAR(pytun_tuntap_close_doc,
             "close() -> None.\n\
Close the device.");

static PyObject *pytun_tuntap_up(PyObject *self) {
    pytun_tuntap_t *tuntap = (pytun_tuntap_t *) self;
    struct ifreq req;

    memset(&req, 0, sizeof(req));
    strcpy(req.ifr_name, tuntap->name);
    if (ioctl(tuntap->fd, SIOCGIFFLAGS, &req) < 0) {
        return NULL;
    }
    if (!(req.ifr_flags & IFF_UP)) {
        req.ifr_flags |= IFF_UP;
        if (ioctl(tuntap->fd, SIOCSIFFLAGS, &req) < 0) {
            return NULL;
        }
    }

    Py_RETURN_NONE;
}

PyDoc_STRVAR(pytun_tuntap_up_doc,
             "up() -> None.\n\
Bring up the device.");

static PyObject *pytun_tuntap_down(PyObject *self) {
    pytun_tuntap_t *tuntap = (pytun_tuntap_t *) self;
    struct ifreq req;

    memset(&req, 0, sizeof(req));
    strcpy(req.ifr_name, tuntap->name);
    if (ioctl(tuntap->fd, SIOCGIFFLAGS, &req) < 0) {
        return NULL;
    }
    if (req.ifr_flags & IFF_UP) {
        req.ifr_flags &= ~IFF_UP;
        if (ioctl(tuntap->fd, SIOCSIFFLAGS, &req) < 0) {
            return NULL;
        }
    }

    Py_RETURN_NONE;
}

PyDoc_STRVAR(pytun_tuntap_down_doc,
             "down() -> None.\n\
Bring down the device.");

static PyObject *pytun_tuntap_read(PyObject *self, PyObject *args) {
    pytun_tuntap_t *tuntap = (pytun_tuntap_t *) self;
    unsigned int rdlen;
    ssize_t outlen;
    PyObject *buf;


    if (!PyArg_ParseTuple(args, "I:read", &rdlen)) {
        return NULL;
    }

    /* Allocate a new string */
#if PY_MAJOR_VERSION >= 3
    buf = PyBytes_FromStringAndSize(NULL, rdlen);
#else
    buf = PyString_FromStringAndSize(NULL, rdlen);
#endif
    if (buf == NULL) {
        return NULL;
    }
    /* Read data */
    Py_BEGIN_ALLOW_THREADS;
#if PY_MAJOR_VERSION >= 3
        outlen = read(tuntap->fd, PyBytes_AS_STRING(buf), rdlen);
#else
        outlen = read(tuntap->fd, PyString_AS_STRING(buf), rdlen);
#endif
    Py_END_ALLOW_THREADS;

    if (outlen < 0) {
        /* An error occurred, release the string and return an error */
        raise_error_from_errno();
        return NULL;
    }
    if (outlen < rdlen) {
        /* We did not read as many bytes as we anticipated, resize the
           string if possible and be successful. */
#if PY_MAJOR_VERSION >= 3
        if (_PyBytes_Resize(&buf, outlen) < 0)
#else
            if (_PyString_Resize(&buf, outlen) < 0)
#endif
        {
            return NULL;
        }
    }

    return buf;
}

PyDoc_STRVAR(pytun_tuntap_read_doc,
             "read(size) -> read at most size bytes, returned as a string.");

static PyObject *pytun_tuntap_write(PyObject *self, PyObject *args) {
    pytun_tuntap_t *tuntap = (pytun_tuntap_t *) self;
    char *buf;
    Py_ssize_t len;
    ssize_t written;

    if (!PyArg_ParseTuple(args, "s#:write", &buf, &len)) {
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
        written = write(tuntap->fd, buf, len);
    Py_END_ALLOW_THREADS
    if (written < 0) {
        raise_error_from_errno();
        return NULL;
    }

#if PY_MAJOR_VERSION >= 3
    return PyLong_FromSsize_t(written);
#else
    return PyInt_FromSsize_t(written);
#endif
}

PyDoc_STRVAR(pytun_tuntap_write_doc,
             "write(str) -> number of bytes written.\n\
Write str to device.");

static PyObject *pytun_tuntap_fileno(PyObject *self) {
#if PY_MAJOR_VERSION >= 3
    return PyLong_FromLong(((pytun_tuntap_t *) self)->fd);
#else
    return PyInt_FromLong(((pytun_tuntap_t*)self)->fd);
#endif
}

PyDoc_STRVAR(pytun_tuntap_fileno_doc,
             "fileno() -> integer \"file descriptor\".");

static PyObject *pytun_tuntap_persist(PyObject *self, PyObject *args) {
    Py_RETURN_NONE;
}

PyDoc_STRVAR(pytun_tuntap_persist_doc,
             "persist(flag) -> None.\n\
Make the TUN/TAP persistent if flags is True else\n\
make it non-persistent.");

#ifdef IFF_MULTI_QUEUE
static PyObject* pytun_tuntap_mq_attach(PyObject* self, PyObject* args)
{
    pytun_tuntap_t* tuntap = (pytun_tuntap_t*)self;
    PyObject* tmp = NULL;
    struct ifreq req;
    int ret;

    if (!PyArg_ParseTuple(args, "|O!:attach", &PyBool_Type, &tmp))
    {
        return NULL;
    }

    memset(&req, 0, sizeof(req));
    if (tmp == NULL || tmp == Py_True)
    {
        req.ifr_flags = IFF_ATTACH_QUEUE;
    }
    else
    {
        req.ifr_flags = IFF_DETACH_QUEUE;
    }

    Py_BEGIN_ALLOW_THREADS
    ret = ioctl(tuntap->fd, TUNSETQUEUE, &req);
    Py_END_ALLOW_THREADS
    if (ret < 0)
    {
        raise_error_from_errno();
        return NULL;
    }

    Py_RETURN_NONE;
}

PyDoc_STRVAR(pytun_tuntap_mq_attach_doc,
"mq_attach(flag) -> None.\n\
Enable the queue if flags is True else\n\
disable the queue.");
#endif

static PyMethodDef pytun_tuntap_meth[] =
        {
                {
                        "close",
                        (PyCFunction) pytun_tuntap_close,
                        METH_NOARGS,
                        pytun_tuntap_close_doc
                },
                {
                        "up",
                        (PyCFunction) pytun_tuntap_up,
                        METH_NOARGS,
                        pytun_tuntap_up_doc
                },
                {
                        "down",
                        (PyCFunction) pytun_tuntap_down,
                        METH_NOARGS,
                        pytun_tuntap_down_doc
                },
                {
                        "read",
                        (PyCFunction) pytun_tuntap_read,
                        METH_VARARGS,
                        pytun_tuntap_read_doc
                },
                {
                        "write",
                        (PyCFunction) pytun_tuntap_write,
                        METH_VARARGS,
                        pytun_tuntap_write_doc
                },
                {
                        "fileno",
                        (PyCFunction) pytun_tuntap_fileno,
                        METH_NOARGS,
                        pytun_tuntap_fileno_doc
                },
                {
                        "persist",
                        (PyCFunction) pytun_tuntap_persist,
                        METH_VARARGS,
                        pytun_tuntap_persist_doc
                },
#ifdef IFF_MULTI_QUEUE
                {
                 "mq_attach",
                 (PyCFunction)pytun_tuntap_mq_attach,
                 METH_VARARGS,
                 pytun_tuntap_mq_attach_doc
                },
#endif
                {NULL, NULL, 0, NULL}
        };

PyDoc_STRVAR(pytun_tuntap_doc,
             "TunTapDevice(name='', flags=IFF_TUN, dev='/dev/net/tun') -> TUN/TAP device object.");

static PyTypeObject pytun_tuntap_type =
        {
                PyVarObject_HEAD_INIT(&PyType_Type, 0)
                .tp_name = "pytun.TunTapDevice",
                .tp_basicsize = sizeof(pytun_tuntap_t),
                .tp_dealloc = pytun_tuntap_dealloc,
                .tp_flags = Py_TPFLAGS_DEFAULT,
                .tp_doc = pytun_tuntap_doc,
                .tp_methods = pytun_tuntap_meth,
                .tp_getset = pytun_tuntap_prop,
                .tp_new = pytun_tuntap_new
        };

#if PY_MAJOR_VERSION >= 3
static struct PyModuleDef pytun_module =
        {
                .m_base = PyModuleDef_HEAD_INIT,
                .m_name = "pytun",
                .m_doc = NULL,
                .m_size = -1,
                .m_methods = NULL,
#if PY_MINOR_VERSION <= 4
                .m_reload = NULL,
#else
                .m_slots = NULL,
#endif
                .m_traverse = NULL,
                .m_clear = NULL,
                .m_free = NULL
        };
#endif

#if PY_MAJOR_VERSION >= 3

PyMODINIT_FUNC PyInit_pytun(void)
#else
PyMODINIT_FUNC initpytun(void)
#endif
{
    PyObject *m;
    PyObject *pytun_error_dict = NULL;

#if PY_MAJOR_VERSION >= 3
    m = PyModule_Create(&pytun_module);
#else
    m = Py_InitModule("pytun", NULL);
#endif
    if (m == NULL) {
        goto error;
    }

    if (PyType_Ready(&pytun_tuntap_type) != 0) {
        goto error;
    }
    Py_INCREF((PyObject *) &pytun_tuntap_type);
    if (PyModule_AddObject(m, "TunTapDevice", (PyObject *) &pytun_tuntap_type) != 0) {
        Py_DECREF((PyObject *) &pytun_tuntap_type);
        goto error;
    }

    pytun_error_dict = Py_BuildValue("{ss}", "__doc__", pytun_error_doc);
    if (pytun_error_dict == NULL) {
        goto error;
    }
    pytun_error = PyErr_NewException("pytun.Error", PyExc_IOError, pytun_error_dict);
    Py_DECREF(pytun_error_dict);
    if (pytun_error == NULL) {
        goto error;
    }
    Py_INCREF(pytun_error);
    if (PyModule_AddObject(m, "Error", pytun_error) != 0) {
        Py_DECREF(pytun_error);
        goto error;
    }

    goto out;

    error:
#if PY_MAJOR_VERSION >= 3
    Py_XDECREF(pytun_error);
    Py_XDECREF(m);
    pytun_error = NULL;
    m = NULL;
#endif

    out:
#if PY_MAJOR_VERSION >= 3
    return m;
#else
    return;
#endif
}

