/*
 * gcc cside.c  -Xlinker -export-dynamic -Wl,-O1 -Wl,-Bsymbolic-functions -I/usr/include/python2.7 -lpython2.7 -o cp.o

 * */


#include <Python.h>

int
main(int argc, char *argv[])
{
    PyObject *pName, *pModule,  *pFunc;
    PyObject *pValue;
    int  is_trusted = 0;

    if (argc < 3) {
        fprintf(stderr,"Usage: call pythonfile funcname [args]\n");
        return 0;
    }
    //Py_SetProgramName("/home/ydurmus/Dropbox/work/eap_stls/c_bridge/webid_bridge");

    Py_Initialize();
    pName = PyString_FromString(argv[1]);
    /* Error checking of pName left out */

    pModule = PyImport_ImportModule(argv[1]);
    Py_DECREF(pName);

    if (pModule != NULL) {
        pFunc = PyObject_GetAttrString(pModule, argv[2]);
        /* pFunc is a new reference */

        if (pFunc && PyCallable_Check(pFunc)) {
        	
        	pValue = PyObject_CallFunction(pFunc,"ss", argv[3], argv[4]);
        	/* pValue is a new reference*/
        	
            
            if (pValue != NULL &&  PyBool_Check(pValue)) {
            	is_trusted = PyObject_IsTrue(pValue);
                printf("Result of call: %d\n",is_trusted);
                Py_DECREF(pValue);
                
            }
            else {
                Py_DECREF(pFunc);
                Py_DECREF(pModule);
                PyErr_Print();
                fprintf(stderr,"Call failed\n");
                return 0;
            }
        }
        else {
            if (PyErr_Occurred())
                PyErr_Print();
            fprintf(stderr, "Cannot find function \"%s\"\n", argv[2]);
        }
        Py_XDECREF(pFunc);
        Py_DECREF(pModule);
    }
    else {
        PyErr_Print();
        fprintf(stderr, "Failed to load \"%s\"\n", argv[1]);
        return 0;
    }
    Py_Finalize();
    return is_trusted;
}
