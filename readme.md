# 按字节分析pyc文件

## 1  前期准备

```shell
➜  pyc tree -s    
.
├── [         30]  index.py
├── [       1947]  readme.md
└── [        128]  simple
    ├── [         96]  __pycache__
    │   └── [        226]  simple.cpython-39.pyc
    └── [         29]  simple.py

2 directories, 4 files
```

首先，建立上述目录及文件。

simple.py文件中的内容很简单，就是一个非常简单的函数：

```python
def add(a,b):
    return a+b
```

index.py文件更简单，

```python
from simple.simple import add
```

然后执行index.py文件，这样就可以生成我们要分析的pyc文件了。从这个pyc文件的名称可以看出我使用的版本是python3.9。最近刚升级的。

这个pyc文件的内容如下所示：

```shell
➜  pyc xxd simple/__pycache__/simple.cpython-39.pyc 
00000000: 610d 0d0a 0000 0000 000e ba5f 1d00 0000  a.........._....
00000010: e300 0000 0000 0000 0000 0000 0000 0000  ................
00000020: 0002 0000 0040 0000 0073 0c00 0000 6400  .....@...s....d.
00000030: 6401 8400 5a00 6402 5300 2903 (6302 0000  d...Z.d.S.).c...
00000040: 0000 0000 0000 0000 0002 0000 0002 0000  ................
00000050: 0043 0000 0073 0800 0000 7c00 7c01 1700  .C...s....|.|...
00000060: 5300 2901 4ea9 0029 02da 0161 da01 6272  S.).N..)...a..br
00000070: 0100 0000 7201 0000 00fa 232f 5573 6572  ....r.....#/User
00000080: 732f 6e65 776c 6966 652f 7079 632f 7369  s/newlife/pyc/si
00000090: 6d70 6c65 2f73 696d 706c 652e 7079 da03  mple/simple.py..
000000a0: 6164 6401 0000 0073 0200 0000 0001) 7205  add....s......r.
000000b0: 0000 004e 2901 7205 0000 0072 0100 0000  ...N).r....r....
000000c0: 7201 0000 0072 0100 0000 7204 0000 00da  r....r....r.....
000000d0: 083c 6d6f 6475 6c65 3e01 0000 00f3 0000  .<module>.......
000000e0: 0000                                     ..
```

## **PyCodeObject**      header部分

### 610d 0d0a === Magic  Number

```python
In [4]: import importlib.util

In [5]: importlib.util.MAGIC_NUMBER
Out[5]: b'a\r\r\n'

In [6]: importlib.util.MAGIC_NUMBER.hex()
Out[6]: '610d0d0a'
```

### 0000 0000 === bit field

这部分内容涉及到`PEP 552 -- Deterministic pycs`，

> The pyc header currently consists of 3 32-bit words. We will expand it to 4. The first word will continue to be the magic number, versioning the bytecode and pyc format. The second word, conceptually the new word, will be a bit field. The interpretation of the rest of the header and invalidation behavior of the pyc depends on the contents of the bit field.
>
> pyc文件的header以前包含3个32位的字，现在要扩展到4个字。第一个字仍然是magic number，表示字节码和pyc的格式版本。第二个字节是新加的，是一个描述符位。header后面的部分解释和pyc的异常行为取决于这个位的内容。

这个位的作用是判断pyc文件是否hashed的，我们这个文件没有，所以后面的部分就是时间戳和文件长度

时间戳的计算：

```python
In [7]: import struct

In [8]: a = b'\x00\x0e\xba\x5f'

In [9]: struct.unpack('I',a)
Out[9]: (1606028800,)
```

文件长度的计算：

```python
In [13]: int('1d',16)
Out[13]: 29
```

对比我们`tree -s`输出的结果，simply.py文件的长度显示29。

## **PyCodeObject**

生成pyc文件的时候，会按照一定的顺序写pycodeobject的各种属性：

```c
        PyCodeObject *co = (PyCodeObject *)v;
        W_TYPE(TYPE_CODE, p);
        w_long(co->co_argcount, p);
        w_long(co->co_posonlyargcount, p);
        w_long(co->co_kwonlyargcount, p);
        w_long(co->co_nlocals, p);
        w_long(co->co_stacksize, p);
        w_long(co->co_flags, p);
        w_object(co->co_code, p);
        w_object(co->co_consts, p);
        w_object(co->co_names, p);
        w_object(co->co_varnames, p);
        w_object(co->co_freevars, p);
        w_object(co->co_cellvars, p);
        w_object(co->co_filename, p);
        w_object(co->co_name, p);
        w_long(co->co_firstlineno, p);
        w_object(co->co_lnotab, p);
```

这段代码摘自`marshal.c`文件。而我们生成的pyc文件自然也是按照这个顺序写的。

| 对象属性YPE                 | hex                           |
| --------------------------- | ----------------------------- |
| TYPE                        | e3  (63)                      |
| co->co_argcount             | 0000 0000                     |
| co_posonlyargcount          | 0000 0000                     |
| co_kwonlyargcount           | 0000 0000                     |
| co_nlocals                  | 0000 0000                     |
| co_stacksize                | 0200 0000 (2)                 |
| co_flags                    | 40 0000 00 (64)               |
| co_code---- TYPE_STRING     | 73                            |
| co_code--- length of STRING | 0c00 0000                     |
| co_code---content           | 6400 6401 8400 5a00 6402 5300 |

在我们分析这些属性之前，我们用python的方式观察这个对象：

```python
In [1]: import dis, marshal

In [2]: f = open("./simple/__pycache__/simple.cpython-39.pyc","rb")

In [3]: f.read(16)
Out[3]: b'a\r\r\n\x00\x00\x00\x00\x00\x0e\xba_\x1d\x00\x00\x00'

In [4]: code = marshal.load(f)

In [6]: for one in dir(code):
   ...:     if not one.startswith("__"):
   ...:         print(one,":",getattr(code,one))
co_argcount : 0
co_posonlyargcount : 0
co_kwonlyargcount : 0
co_nlocals : 0
co_stacksize : 2
co_flags : 64    
co_code : b'd\x00d\x01\x84\x00Z\x00d\x02S\x00'
co_consts : (<code object add at 0x10fd6bd40, file "/Users/newlife/pyc/simple/simple.py", line 1>, 'add', None)
co_names : ('add',)   
co_varnames : ()   
co_freevars : () 
co_cellvars : ()
co_filename : /Users/newlife/pyc/simple/simple.py
co_name : <module>    
co_firstlineno : 1
co_lnotab : b''
```

在写入pyc文件时，首先要存储写入对象的类型。这里的`e3`就是code type的类型，

```c
#define TYPE_CODE               'c'
#define TYPE_TUPLE              '('
#define TYPE_REF                'r'
#define TYPE_NONE               'N'


#define W_TYPE(t, p) do { \
    w_byte((t) | flag, (p)); \
} while(0)

#define FLAG_REF                '\x80' /* with a type, add obj to index */

static int
w_ref(PyObject *v, char *flag, WFILE *p)
{
    _Py_hashtable_entry_t *entry;
    int w;

    if (p->version < 3 || p->hashtable == NULL)
        return 0; /* not writing object references */

    /* if it has only one reference, it definitely isn't shared */
    if (Py_REFCNT(v) == 1)
        return 0;

    entry = _Py_hashtable_get_entry(p->hashtable, v);
    if (entry != NULL) {
        /* write the reference index to the stream */
        w = (int)(uintptr_t)entry->value;
        /* we don't store "long" indices in the dict */
        assert(0 <= w && w <= 0x7fffffff);
        w_byte(TYPE_REF, p);
        w_long(w, p);
        return 1;
    } else {
        size_t s = p->hashtable->nentries;
        /* we don't support long indices */
        if (s >= 0x7fffffff) {
            PyErr_SetString(PyExc_ValueError, "too many objects");
            goto err;
        }
        w = (int)s;
        Py_INCREF(v);
        if (_Py_hashtable_set(p->hashtable, v, (void *)(uintptr_t)w) < 0) {
            Py_DECREF(v);
            goto err;
        }
        *flag |= FLAG_REF;
        return 0;
    }
err:
    p->error = WFERR_UNMARSHALLABLE;
    return 1;
}
#在这个函数中flag被定义为FLAG_REF('\x80')
```

就是`'c'`了，

```shell
In [1]: 0x63|0x80
Out[1]: 227

In [2]: hex(227)
Out[2]: '0xe3'
```

紧接着就是`co_code`的部分，这个部分是以`TYPE_STRING`的格式存的，就是's',然后是这个string的长度12（"c"）

### co_consts

这个co_consts的类型是TYPE_TUPLE，`）`, 显示29，然后就是tuple的长度3。这个三个元素分别是一个code object，string`add`，最后是None。

然后是重复上面的过程：



| TYPE  code                    | 63  (63)                                             |
| ----------------------------- | ---------------------------------------------------- |
| co->co_argcount               | 0200 0000                                            |
| co_posonlyargcount            | 0000 0000                                            |
| co_kwonlyargcount             | 0000 0000                                            |
| co_nlocals                    | 0200 0000                                            |
| co_stacksize                  | 0200 0000                                            |
| co_flags                      | 4300 0000 （67）                                     |
| co_code (type + length)       | 73  0800 0000                                        |
| co_code(content)              | 7c00 7c01 1700 5300                                  |
| co_consts(tuple, 1个元素)     | 29 01                                                |
| co_consts (content)           | 4e (NONE)                                            |
| co_names (empty tuple)        | a9 00 (29)                                           |
| co_varnames（2个元素的tuple） | 29 02                                                |
| co_varnames (content)         | da 0161 da01 62                                      |
| co_freevars                   | 72  0100 0000                                        |
| co_cellvars                   | 72  0100 0000                                        |
| co_filename(type, length)     | fa 2b (fa=='z',2b=43)                                |
| o_filename(content)           | 2f 7079 632f 7369 6d70 6c65 2f73 696d 706c 652e 7079 |
| co_name                       | da 03 6164 64                                        |
| co_firstlineno                | 0100 0000                                            |
| co_lnotab                     | 73 02 0000 0001                                      |
|                               |                                                      |

