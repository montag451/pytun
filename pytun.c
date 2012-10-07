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

static PyObject* pytun_error;

PyDoc_STRVAR(pytun_error_doc,
"This exception is raised when an error occurs.The accompanying value is\n\
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

    return PyString_FromString(tuntap->name);
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

    return PyString_FromString(addr);
}

static int pytun_tuntap_set_addr(PyObject* self, PyObject* value, void* d)
{
    pytun_tuntap_t* tuntap = (pytun_tuntap_t*)self;
    struct ifreq req;
    const char* addr;
    struct sockaddr_in* sin;

    addr = PyString_AsString(value);
    if (addr == NULL)
    {
        return -1;
    }
    memset(&req, 0, sizeof(req));
    strcpy(req.ifr_name, tuntap->name);
    sin = (struct sockaddr_in*)&req.ifr_addr;
    sin->sin_family = AF_INET;
    if (inet_aton(addr, &sin->sin_addr) < 0)
    {
        raise_error("Bad IP address");
        return -1;
    }
    if (if_ioctl(SIOCSIFADDR, &req) < 0)
    {
        return -1;
    }

    return 0;
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

    return PyString_FromString(dstaddr);
}

static int pytun_tuntap_set_dstaddr(PyObject* self, PyObject* value, void* d)
{
    pytun_tuntap_t* tuntap = (pytun_tuntap_t*)self;
    struct ifreq req;
    const char* dstaddr;
    struct sockaddr_in* sin;

    dstaddr = PyString_AsString(value);
    if (dstaddr == NULL)
    {
        return -1;
    }
    memset(&req, 0, sizeof(req));
    strcpy(req.ifr_name, tuntap->name);
    sin = (struct sockaddr_in*)&req.ifr_dstaddr;
    sin->sin_family = AF_INET;
    if (inet_aton(dstaddr, &sin->sin_addr) < 0)
    {
        raise_error("Bad IP address");
        return -1;
    }
    if (if_ioctl(SIOCSIFDSTADDR, &req) < 0)
    {
        return -1;
    }

    return 0;
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

    return PyString_FromStringAndSize(req.ifr_hwaddr.sa_data, ETH_ALEN);
}

static int pytun_tuntap_set_hwaddr(PyObject* self, PyObject* value, void* d)
{
    pytun_tuntap_t* tuntap = (pytun_tuntap_t*)self;
    struct ifreq req;
    char* hwaddr;
    Py_ssize_t len;

    if (PyString_AsStringAndSize(value, &hwaddr, &len) == -1)
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

    return PyString_FromString(netmask);
}

static int pytun_tuntap_set_netmask(PyObject* self, PyObject* value, void* d)
{
    pytun_tuntap_t* tuntap = (pytun_tuntap_t*)self;
    struct ifreq req;
    const char* netmask;
    struct sockaddr_in* sin;

    netmask = PyString_AsString(value);
    if (netmask == NULL)
    {
        return -1;
    }
    memset(&req, 0, sizeof(req));
    strcpy(req.ifr_name, tuntap->name);
    sin = (struct sockaddr_in*)&req.ifr_netmask;
    sin->sin_family = AF_INET;
    if (inet_aton(netmask, &sin->sin_addr) < 0)
    {
        raise_error("Bad IP address");
        return -1;
    }
    if (if_ioctl(SIOCSIFNETMASK, &req) < 0)
    {
        return -1;
    }

    return 0;
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

    return PyInt_FromLong(req.ifr_mtu);
}

static int pytun_tuntap_set_mtu(PyObject* self, PyObject* value, void* d)
{
    pytun_tuntap_t* tuntap = (pytun_tuntap_t*)self;
    struct ifreq req;
    int mtu;

    mtu = PyInt_AsLong(value);
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
    {"name", pytun_tuntap_get_name, NULL, NULL, NULL},
    {"addr", pytun_tuntap_get_addr, pytun_tuntap_set_addr, NULL, NULL},
    {"dstaddr", pytun_tuntap_get_dstaddr, pytun_tuntap_set_dstaddr, NULL, NULL},
    {"hwaddr", pytun_tuntap_get_hwaddr, pytun_tuntap_set_hwaddr, NULL, NULL},
    {"netmask", pytun_tuntap_get_netmask, pytun_tuntap_set_netmask, NULL, NULL},
    {"mtu", pytun_tuntap_get_mtu, pytun_tuntap_set_mtu, NULL, NULL},
    {NULL, NULL, NULL, NULL, NULL}
};

static PyObject* pytun_tuntap_close(PyObject* self)
{
    pytun_tuntap_t* tuntap = (pytun_tuntap_t*)self;

    if (tuntap->fd >= 0)
    {
        Py_BEGIN_ALLOW_THREADS
        close(tuntap->fd);
        Py_END_ALLOW_THREADS
    }

    Py_RETURN_NONE;
}

PyDoc_STRVAR(pytun_tuntap_close_doc,
"close() -> None. Close the device.");

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
"up() -> None. Bring up the device.");

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
"down() -> None. Bring down the device.");

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
    buf = PyString_FromStringAndSize(NULL, rdlen);
    if (buf == NULL)
    {
        return NULL;
    }

    /* Read data */
    Py_BEGIN_ALLOW_THREADS
    outlen = read(tuntap->fd, PyString_AS_STRING(buf), rdlen);
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
        if (_PyString_Resize(&buf, outlen) < 0)
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
    int len;
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

    return PyInt_FromSsize_t(written);
}

PyDoc_STRVAR(pytun_tuntap_write_doc,
"write(str) -> number of bytes written. Write str to device.");

static PyObject* pytun_tuntap_fileno(PyObject* self)
{
    return PyInt_FromLong(((pytun_tuntap_t*)self)->fd);
}

PyDoc_STRVAR(pytun_tuntap_fileno_doc,
"fileno() -> integer \"file descriptor\"");

static PyMethodDef pytun_tuntap_meth[] =
{
    {"close", (PyCFunction)pytun_tuntap_close, METH_NOARGS, pytun_tuntap_close_doc},
    {"up", (PyCFunction)pytun_tuntap_up, METH_NOARGS, pytun_tuntap_up_doc},
    {"down", (PyCFunction)pytun_tuntap_down, METH_NOARGS, pytun_tuntap_down_doc},
    {"read", (PyCFunction)pytun_tuntap_read, METH_VARARGS, pytun_tuntap_read_doc},
    {"write", (PyCFunction)pytun_tuntap_write, METH_VARARGS, pytun_tuntap_write_doc},
    {"fileno", (PyCFunction)pytun_tuntap_fileno, METH_NOARGS, pytun_tuntap_fileno_doc},
    {NULL, NULL, 0, NULL}
};

PyDoc_STRVAR(pytun_tuntap_doc,
"TunTapDevice(name='', flags=IFF_TUN, dev='/dev/net/tun') -> TUN/TAP device object");

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

PyMODINIT_FUNC initpytun(void)
{
    PyObject* m;
    PyObject* pytun_error_dict;

    m = Py_InitModule("pytun", NULL);
    if (m == NULL)
    {
        return;
    }

    if (PyType_Ready(&pytun_tuntap_type) != 0)
    {
        return;
    }
    Py_INCREF((PyObject*)&pytun_tuntap_type);
    if (PyModule_AddObject(m, "TunTapDevice", (PyObject*)&pytun_tuntap_type) != 0)
    {
        return;
    }

    pytun_error_dict = Py_BuildValue("{ss}", "__doc__", pytun_error_doc);
    if (pytun_error_dict == NULL)
    {
        return;
    }
    pytun_error = PyErr_NewException("pytun.Error", PyExc_IOError, pytun_error_dict);
    Py_DECREF(pytun_error_dict);
    if (pytun_error == NULL)
    {
        return;
    }
    Py_INCREF(pytun_error);
    if (PyModule_AddObject(m, "Error", pytun_error) != 0)
    {
        return;
    }

    PyModule_AddIntConstant(m, "IFF_TUN", IFF_TUN);
    PyModule_AddIntConstant(m, "IFF_TAP", IFF_TAP);
#ifdef IFF_NO_PI
    PyModule_AddIntConstant(m, "IFF_NO_PI", IFF_NO_PI);
#endif
#ifdef IFF_ONE_QUEUE
    PyModule_AddIntConstant(m, "IFF_ONE_QUEUE", IFF_ONE_QUEUE);
#endif
#ifdef IFF_VNET_HDR
    PyModule_AddIntConstant(m, "IFF_VNET_HDR", IFF_VNET_HDR);
#endif
#ifdef IFF_TUN_EXCL
    PyModule_AddIntConstant(m, "IFF_TUN_EXCL", IFF_TUN_EXCL);
#endif
}

