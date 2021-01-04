#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <linux/if_tun.h>
#include <arpa/inet.h>

#ifndef PyVarObject_HEAD_INIT
#define PyVarObject_HEAD_INIT(type, size) \
    PyObject_HEAD_INIT(type) size,
#endif

static PyObject* pytun_error = NULL;

PyDoc_STRVAR(pytun_error_doc,
"This exception is raised when an error occurs. The accompanying value is\n\
either a string telling what went wrong or a pair (errno, string)\n\
representing an error returned by a system call, similar to the value\n\
accompanying os.error. See the module errno, which contains names for the\n\
error codes defined by the underlying operating system.");

static void raise_error(const char* errmsg)
{
    PyErr_SetString(pytun_error, errmsg);
}

static void raise_error_from_errno(void)
{
    PyErr_SetFromErrno(pytun_error);
}

static int if_ioctl(int cmd, struct ifreq* req)
{
    int ret;
    int sock;

    Py_BEGIN_ALLOW_THREADS
    sock = socket(AF_INET, SOCK_DGRAM, 0);
    Py_END_ALLOW_THREADS
    if (sock < 0)
    {
        raise_error_from_errno();
        return -1;
    }
    Py_BEGIN_ALLOW_THREADS
    ret = ioctl(sock, cmd, req);
    Py_END_ALLOW_THREADS
    if (ret < 0)
    {
        raise_error_from_errno();
    }
    Py_BEGIN_ALLOW_THREADS
    close(sock);
    Py_END_ALLOW_THREADS

    return ret;
}

struct pytun_tuntap
{
    PyObject_HEAD
    int fd;
    char name[IFNAMSIZ];
};
typedef struct pytun_tuntap pytun_tuntap_t;

static PyObject* pytun_tuntap_new(PyTypeObject* type, PyObject* args, PyObject* kwds)
{
    pytun_tuntap_t* tuntap = NULL;
    const char* name = "";
    int flags = IFF_TUN;
    const char* dev = "/dev/net/tun";
    char* kwlist[] = {"name", "flags", "dev", NULL};
    int ret;
    const char* errmsg = NULL;
    struct ifreq req;

    if (!PyArg_ParseTupleAndKeywords(args, kwds, "|sis", kwlist, &name, &flags, &dev))
    {
        return NULL;
    }

    /* Check flags value */
    if (!(flags & (IFF_TUN | IFF_TAP)))
    {
        errmsg = "Bad flags: either IFF_TUN or IFF_TAP must be set";
        goto error;
    }
    if ((flags & IFF_TUN) && (flags & IFF_TAP))
    {
        errmsg = "Bad flags: IFF_TUN and IFF_TAP could not both be set";
        goto error;
    }

    /* Check the name length */
    if (strlen(name) >= IFNAMSIZ)
    {
        errmsg = "Interface name too long";
        goto error;
    }

    tuntap = (pytun_tuntap_t*)type->tp_alloc(type, 0);
    if (tuntap == NULL)
    {
        goto error;
    }

    /* Open the TUN/TAP device */
    Py_BEGIN_ALLOW_THREADS
    tuntap->fd = open(dev, O_RDWR);
    Py_END_ALLOW_THREADS
    if (tuntap->fd < 0)
    {
        goto error;
    }

    /* Prepare the structure used to issue ioctl() calls */
    memset(&req, 0, sizeof(req));
    if (*name)
    {
        strcpy(req.ifr_name, name);
    }

    /* Create the TUN/TAP interface */
    req.ifr_flags = flags;
    Py_BEGIN_ALLOW_THREADS
    ret = ioctl(tuntap->fd, TUNSETIFF, &req);
    Py_END_ALLOW_THREADS
    if (ret < 0)
    {
        goto error;
    }
    strcpy(tuntap->name, req.ifr_name);

    return (PyObject*)tuntap;

error:

    if (errmsg != NULL)
    {
        raise_error(errmsg);
    }
    else if (errno != 0)
    {
        raise_error_from_errno();
    }

    if (tuntap != NULL)
    {
        if (tuntap->fd >= 0)
        {
            Py_BEGIN_ALLOW_THREADS
            close(tuntap->fd);
            Py_END_ALLOW_THREADS
        }
        type->tp_free(tuntap);
    }

    return NULL;
}

static void pytun_tuntap_dealloc(PyObject* self)
{
    pytun_tuntap_t* tuntap = (pytun_tuntap_t*)self;

    if (tuntap->fd >= 0)
    {
        Py_BEGIN_ALLOW_THREADS
        close(tuntap->fd);
        Py_END_ALLOW_THREADS
    }
    self->ob_type->tp_free(self);
}

static PyObject* pytun_tuntap_get_name(PyObject* self, void* d)
{
    pytun_tuntap_t* tuntap = (pytun_tuntap_t*)self;

#if PY_MAJOR_VERSION >= 3
    return PyUnicode_FromString(tuntap->name);
#else
    return PyString_FromString(tuntap->name);
#endif
}

static PyObject* pytun_tuntap_get_addr(PyObject* self, void* d)
{
    pytun_tuntap_t* tuntap = (pytun_tuntap_t*)self;
    struct ifreq req;
    const char* addr;

    memset(&req, 0, sizeof(req));
    strcpy(req.ifr_name, tuntap->name);
    if (if_ioctl(SIOCGIFADDR, &req) < 0)
    {
        return NULL;
    }
    addr = inet_ntoa(((struct sockaddr_in*)&req.ifr_addr)->sin_addr);
    if (addr == NULL)
    {
        raise_error("Failed to retrieve addr");
        return NULL;
    }

#if PY_MAJOR_VERSION >= 3
    return PyUnicode_FromString(addr);
#else
    return PyString_FromString(addr);
#endif
}

static int pytun_tuntap_set_addr(PyObject* self, PyObject* value, void* d)
{
    pytun_tuntap_t* tuntap = (pytun_tuntap_t*)self;
    int ret = 0;
    struct ifreq req;
#if PY_MAJOR_VERSION >= 3
    PyObject* tmp_addr;
#endif
    const char* addr;
    struct sockaddr_in* sin;

#if PY_MAJOR_VERSION >= 3
    tmp_addr = PyUnicode_AsASCIIString(value);
    addr = tmp_addr != NULL ? PyBytes_AS_STRING(tmp_addr) : NULL;
#else
    addr = PyString_AsString(value);
#endif
    if (addr == NULL)
    {
        ret = -1;
        goto out;
    }
    memset(&req, 0, sizeof(req));
    strcpy(req.ifr_name, tuntap->name);
    sin = (struct sockaddr_in*)&req.ifr_addr;
    sin->sin_family = AF_INET;
    if (inet_aton(addr, &sin->sin_addr) == 0)
    {
        raise_error("Bad IP address");
        ret = -1;
        goto out;
    }
    if (if_ioctl(SIOCSIFADDR, &req) < 0)
    {
        ret = -1;
        goto out;
    }

out:
#if PY_MAJOR_VERSION >= 3
    Py_XDECREF(tmp_addr);
#endif

    return ret;
}

static PyObject* pytun_tuntap_get_dstaddr(PyObject* self, void* d)
{
    pytun_tuntap_t* tuntap = (pytun_tuntap_t*)self;
    struct ifreq req;
    const char* dstaddr;

    memset(&req, 0, sizeof(req));
    strcpy(req.ifr_name, tuntap->name);
    if (if_ioctl(SIOCGIFDSTADDR, &req) < 0)
    {
        return NULL;
    }
    dstaddr = inet_ntoa(((struct sockaddr_in*)&req.ifr_dstaddr)->sin_addr);
    if (dstaddr == NULL)
    {
        raise_error("Failed to retrieve dstaddr");
        return NULL;
    }

#if PY_MAJOR_VERSION >= 3
    return PyUnicode_FromString(dstaddr);
#else
    return PyString_FromString(dstaddr);
#endif
}

static int pytun_tuntap_set_dstaddr(PyObject* self, PyObject* value, void* d)
{
    pytun_tuntap_t* tuntap = (pytun_tuntap_t*)self;
    int ret = 0;
    struct ifreq req;
#if PY_MAJOR_VERSION >= 3
    PyObject* tmp_dstaddr;
#endif
    const char* dstaddr;
    struct sockaddr_in* sin;

#if PY_MAJOR_VERSION >= 3
    tmp_dstaddr = PyUnicode_AsASCIIString(value);
    dstaddr = tmp_dstaddr != NULL ? PyBytes_AS_STRING(tmp_dstaddr) : NULL;
#else
    dstaddr = PyString_AsString(value);
#endif
    if (dstaddr == NULL)
    {
        ret = -1;
        goto out;
    }
    memset(&req, 0, sizeof(req));
    strcpy(req.ifr_name, tuntap->name);
    sin = (struct sockaddr_in*)&req.ifr_dstaddr;
    sin->sin_family = AF_INET;
    if (inet_aton(dstaddr, &sin->sin_addr) == 0)
    {
        raise_error("Bad IP address");
        ret = -1;
        goto out;
    }
    if (if_ioctl(SIOCSIFDSTADDR, &req) < 0)
    {
        ret = -1;
        goto out;
    }

out:
#if PY_MAJOR_VERSION >= 3
    Py_XDECREF(tmp_dstaddr);
#endif

    return ret;
}

static PyObject* pytun_tuntap_get_hwaddr(PyObject* self, void* d)
{
    pytun_tuntap_t* tuntap = (pytun_tuntap_t*)self;
    struct ifreq req;

    memset(&req, 0, sizeof(req));
    strcpy(req.ifr_name, tuntap->name);
    if (if_ioctl(SIOCGIFHWADDR, &req) < 0)
    {
        return NULL;
    }

#if PY_MAJOR_VERSION >= 3
    return PyBytes_FromStringAndSize(req.ifr_hwaddr.sa_data, ETH_ALEN);
#else
    return PyString_FromStringAndSize(req.ifr_hwaddr.sa_data, ETH_ALEN);
#endif
}

static int pytun_tuntap_set_hwaddr(PyObject* self, PyObject* value, void* d)
{
    pytun_tuntap_t* tuntap = (pytun_tuntap_t*)self;
    struct ifreq req;
    char* hwaddr;
    Py_ssize_t len;

#if PY_MAJOR_VERSION >= 3
    if (PyBytes_AsStringAndSize(value, &hwaddr, &len) == -1)
#else
    if (PyString_AsStringAndSize(value, &hwaddr, &len) == -1)
#endif
    {
        return -1;
    }
    if (len != ETH_ALEN)
    {
        raise_error("Bad MAC address");
        return -1;
    }
    memset(&req, 0, sizeof(req));
    strcpy(req.ifr_name, tuntap->name);
    req.ifr_hwaddr.sa_family = ARPHRD_ETHER;
    memcpy(req.ifr_hwaddr.sa_data, hwaddr, len);
    if (if_ioctl(SIOCSIFHWADDR, &req) < 0)
    {
        return -1;
    }

    return 0;
}

static PyObject* pytun_tuntap_get_netmask(PyObject* self, void* d)
{
    pytun_tuntap_t* tuntap = (pytun_tuntap_t*)self;
    struct ifreq req;
    const char* netmask;

    memset(&req, 0, sizeof(req));
    strcpy(req.ifr_name, tuntap->name);
    if (if_ioctl(SIOCGIFNETMASK, &req) < 0)
    {
        return NULL;
    }
    netmask = inet_ntoa(((struct sockaddr_in*)&req.ifr_netmask)->sin_addr);
    if (netmask == NULL)
    {
        raise_error("Failed to retrieve netmask");
        return NULL;
    }

#if PY_MAJOR_VERSION >= 3
    return PyUnicode_FromString(netmask);
#else
    return PyString_FromString(netmask);
#endif
}

static int pytun_tuntap_set_netmask(PyObject* self, PyObject* value, void* d)
{
    pytun_tuntap_t* tuntap = (pytun_tuntap_t*)self;
    int ret = 0;
    struct ifreq req;
#if PY_MAJOR_VERSION >= 3
    PyObject* tmp_netmask;
#endif
    const char* netmask;
    struct sockaddr_in* sin;

#if PY_MAJOR_VERSION >= 3
    tmp_netmask = PyUnicode_AsASCIIString(value);
    netmask = tmp_netmask != NULL ? PyBytes_AS_STRING(tmp_netmask) : NULL;
#else
    netmask = PyString_AsString(value);
#endif
    if (netmask == NULL)
    {
        ret = -1;
        goto out;
    }
    memset(&req, 0, sizeof(req));
    strcpy(req.ifr_name, tuntap->name);
    sin = (struct sockaddr_in*)&req.ifr_netmask;
    sin->sin_family = AF_INET;
    if (inet_aton(netmask, &sin->sin_addr) == 0)
    {
        raise_error("Bad IP address");
        ret = -1;
        goto out;
    }
    if (if_ioctl(SIOCSIFNETMASK, &req) < 0)
    {
        ret = -1;
        goto out;
    }

out:
#if PY_MAJOR_VERSION >= 3
    Py_XDECREF(tmp_netmask);
#endif

    return ret;
}

static PyObject* pytun_tuntap_get_mtu(PyObject* self, void* d)
{
    pytun_tuntap_t* tuntap = (pytun_tuntap_t*)self;
    struct ifreq req;

    memset(&req, 0, sizeof(req));
    strcpy(req.ifr_name, tuntap->name);
    if (if_ioctl(SIOCGIFMTU, &req) < 0)
    {
        return NULL;
    }

#if PY_MAJOR_VERSION >= 3
    return PyLong_FromLong(req.ifr_mtu);
#else
    return PyInt_FromLong(req.ifr_mtu);
#endif
}

static int pytun_tuntap_set_mtu(PyObject* self, PyObject* value, void* d)
{
    pytun_tuntap_t* tuntap = (pytun_tuntap_t*)self;
    struct ifreq req;
    int mtu;

    mtu = PyLong_AsLong(value);
    if (mtu <= 0)
    {
        if (!PyErr_Occurred())
        {
            raise_error("Bad MTU, should be > 0");
        }
        return -1;
    }
    memset(&req, 0, sizeof(req));
    strcpy(req.ifr_name, tuntap->name);
    req.ifr_mtu = mtu;
    if (if_ioctl(SIOCSIFMTU, &req) < 0)
    {
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
     pytun_tuntap_get_addr,
     pytun_tuntap_set_addr,
     NULL,
     NULL
    },
    {
     "dstaddr",
     pytun_tuntap_get_dstaddr,
     pytun_tuntap_set_dstaddr,
     NULL, NULL
    },
    {
     "hwaddr",
     pytun_tuntap_get_hwaddr,
     pytun_tuntap_set_hwaddr,
     NULL,
     NULL
    },
    {
     "netmask",
     pytun_tuntap_get_netmask,
     pytun_tuntap_set_netmask,
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
    {NULL, NULL, NULL, NULL, NULL}
};

static PyObject* pytun_tuntap_close(PyObject* self)
{
    pytun_tuntap_t* tuntap = (pytun_tuntap_t*)self;

    if (tuntap->fd >= 0)
    {
        Py_BEGIN_ALLOW_THREADS
        close(tuntap->fd), tuntap->fd = -1;
        Py_END_ALLOW_THREADS
    }

    Py_RETURN_NONE;
}

PyDoc_STRVAR(pytun_tuntap_close_doc,
"close() -> None.\n\
Close the device.");

static PyObject* pytun_tuntap_up(PyObject* self)
{
    pytun_tuntap_t* tuntap = (pytun_tuntap_t*)self;
    struct ifreq req;

    memset(&req, 0, sizeof(req));
    strcpy(req.ifr_name, tuntap->name);
    if (if_ioctl(SIOCGIFFLAGS, &req) < 0)
    {
        return NULL;
    }
    if (!(req.ifr_flags & IFF_UP))
    {
        req.ifr_flags |= IFF_UP;
        if (if_ioctl(SIOCSIFFLAGS, &req) < 0)
        {
            return NULL;
        }
    }

    Py_RETURN_NONE;
}

PyDoc_STRVAR(pytun_tuntap_up_doc,
"up() -> None.\n\
Bring up the device.");

static PyObject* pytun_tuntap_down(PyObject* self)
{
    pytun_tuntap_t* tuntap = (pytun_tuntap_t*)self;
    struct ifreq req;

    memset(&req, 0, sizeof(req));
    strcpy(req.ifr_name, tuntap->name);
    if (if_ioctl(SIOCGIFFLAGS, &req) < 0)
    {
        return NULL;
    }
    if (req.ifr_flags & IFF_UP)
    {
        req.ifr_flags &= ~IFF_UP;
        if (if_ioctl(SIOCSIFFLAGS, &req) < 0)
        {
            return NULL;
        }
    }

    Py_RETURN_NONE;
}

PyDoc_STRVAR(pytun_tuntap_down_doc,
"down() -> None.\n\
Bring down the device.");

static PyObject* pytun_tuntap_read(PyObject* self, PyObject* args)
{
    pytun_tuntap_t* tuntap = (pytun_tuntap_t*)self;
    unsigned int rdlen;
    ssize_t outlen;
    PyObject *buf;

    if (!PyArg_ParseTuple(args, "I:read", &rdlen))
    {
        return NULL;
    }

    /* Allocate a new string */
#if PY_MAJOR_VERSION >= 3
    buf = PyBytes_FromStringAndSize(NULL, rdlen);
#else
    buf = PyString_FromStringAndSize(NULL, rdlen);
#endif
    if (buf == NULL)
    {
        return NULL;
    }

    /* Read data */
    Py_BEGIN_ALLOW_THREADS
#if PY_MAJOR_VERSION >= 3
    outlen = read(tuntap->fd, PyBytes_AS_STRING(buf), rdlen);
#else
    outlen = read(tuntap->fd, PyString_AS_STRING(buf), rdlen);
#endif
    Py_END_ALLOW_THREADS
    if (outlen < 0)
    {
        /* An error occurred, release the string and return an error */
        raise_error_from_errno();
        Py_DECREF(buf);
        return NULL;
    }
    if (outlen < rdlen)
    {
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

static PyObject* pytun_tuntap_write(PyObject* self, PyObject* args)
{
    pytun_tuntap_t* tuntap = (pytun_tuntap_t*)self;
    char* buf;
    Py_ssize_t len;
    ssize_t written;

    if (!PyArg_ParseTuple(args, "s#:write", &buf, &len))
    {
        return NULL;
    }

    Py_BEGIN_ALLOW_THREADS
    written = write(tuntap->fd, buf, len);
    Py_END_ALLOW_THREADS
    if (written < 0)
    {
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

static PyObject* pytun_tuntap_fileno(PyObject* self)
{
#if PY_MAJOR_VERSION >= 3
    return PyLong_FromLong(((pytun_tuntap_t*)self)->fd);
#else
    return PyInt_FromLong(((pytun_tuntap_t*)self)->fd);
#endif
}

PyDoc_STRVAR(pytun_tuntap_fileno_doc,
"fileno() -> integer \"file descriptor\".");

static PyObject* pytun_tuntap_persist(PyObject* self, PyObject* args)
{
    pytun_tuntap_t* tuntap = (pytun_tuntap_t*)self;
    PyObject* tmp = NULL;
    int persist;
    int ret;

    if (!PyArg_ParseTuple(args, "|O!:persist", &PyBool_Type, &tmp))
    {
        return NULL;
    }

    if (tmp == NULL || tmp == Py_True)
    {
        persist = 1;
    }
    else
    {
        persist = 0;
    }

    Py_BEGIN_ALLOW_THREADS
    ret = ioctl(tuntap->fd, TUNSETPERSIST, persist);
    Py_END_ALLOW_THREADS
    if (ret < 0)
    {
        raise_error_from_errno();
        return NULL;
    }

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
     (PyCFunction)pytun_tuntap_close,
     METH_NOARGS,
     pytun_tuntap_close_doc
    },
    {
     "up",
     (PyCFunction)pytun_tuntap_up,
     METH_NOARGS,
     pytun_tuntap_up_doc
    },
    {
     "down",
     (PyCFunction)pytun_tuntap_down,
     METH_NOARGS,
     pytun_tuntap_down_doc
    },
    {
     "read",
     (PyCFunction)pytun_tuntap_read,
     METH_VARARGS,
     pytun_tuntap_read_doc
    },
    {
     "write",
     (PyCFunction)pytun_tuntap_write,
     METH_VARARGS,
     pytun_tuntap_write_doc
    },
    {
     "fileno",
     (PyCFunction)pytun_tuntap_fileno,
     METH_NOARGS,
     pytun_tuntap_fileno_doc
    },
    {
     "persist",
     (PyCFunction)pytun_tuntap_persist,
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
    PyObject* m;
    PyObject* pytun_error_dict = NULL;

#if PY_MAJOR_VERSION >= 3
    m = PyModule_Create(&pytun_module);
#else
    m = Py_InitModule("pytun", NULL);
#endif
    if (m == NULL)
    {
        goto error;
    }

    if (PyType_Ready(&pytun_tuntap_type) != 0)
    {
        goto error;
    }
    Py_INCREF((PyObject*)&pytun_tuntap_type);
    if (PyModule_AddObject(m, "TunTapDevice", (PyObject*)&pytun_tuntap_type) != 0)
    {
        Py_DECREF((PyObject*)&pytun_tuntap_type);
        goto error;
    }

    pytun_error_dict = Py_BuildValue("{ss}", "__doc__", pytun_error_doc);
    if (pytun_error_dict == NULL)
    {
        goto error;
    }
    pytun_error = PyErr_NewException("pytun.Error", PyExc_IOError, pytun_error_dict);
    Py_DECREF(pytun_error_dict);
    if (pytun_error == NULL)
    {
        goto error;
    }
    Py_INCREF(pytun_error);
    if (PyModule_AddObject(m, "Error", pytun_error) != 0)
    {
        Py_DECREF(pytun_error);
        goto error;
    }

    if (PyModule_AddIntConstant(m, "IFF_TUN", IFF_TUN) != 0)
    {
        goto error;
    }
    if (PyModule_AddIntConstant(m, "IFF_TAP", IFF_TAP) != 0)
    {
        goto error;
    }
#ifdef IFF_NO_PI
    if (PyModule_AddIntConstant(m, "IFF_NO_PI", IFF_NO_PI) != 0)
    {
        goto error;
    }
#endif
#ifdef IFF_ONE_QUEUE
    if (PyModule_AddIntConstant(m, "IFF_ONE_QUEUE", IFF_ONE_QUEUE) != 0)
    {
        goto error;
    }
#endif
#ifdef IFF_VNET_HDR
    if (PyModule_AddIntConstant(m, "IFF_VNET_HDR", IFF_VNET_HDR) != 0)
    {
        goto error;
    }
#endif
#ifdef IFF_TUN_EXCL
    if (PyModule_AddIntConstant(m, "IFF_TUN_EXCL", IFF_TUN_EXCL) != 0)
    {
        goto error;
    }
#endif
#ifdef IFF_MULTI_QUEUE
    if (PyModule_AddIntConstant(m, "IFF_MULTI_QUEUE", IFF_MULTI_QUEUE) != 0)
    {
        goto error;
    }
#endif

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

