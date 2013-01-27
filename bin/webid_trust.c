/*
 * gcc cside.c  -Xlinker -export-dynamic -Wl,-O1 -Wl,-Bsymbolic-functions -I/usr/include/python2.7 -lpython2.7 -o cp.o

 * */


#include <Python.h>
#include "cbridge.h"
#include <stdio.h>


int
trust(const char* auth_uri, const char* san_uri, char* method)
{
    PyObject  *pModule;
    PyObject *pValue;
    int  is_trusted = 0;


    //Py_SetProgramName("/home/ydurmus/Dropbox/work/eap_stls/c_bridge/webid_bridge");

    Py_Initialize();

    /* Error checking of pName left out */

    pModule = PyImport_ImportModule(WEBID_MODULE);


    if (pModule != NULL) {
//        pFunc = PyObject_GetAttrString(pModule, method);
        /* pFunc is a new reference */
        // WE DONOT NEED pFunc if we can use call method system

//        if (pFunc && PyCallable_Check(pFunc)) {
        	
        	//pValue = PyObject_CallFunction(pFunc,"ss", auth_uri, san_uri);
        	pValue = PyObject_CallMethod(pModule,method,"ss", auth_uri, san_uri);
        	/* pValue is a new reference*/
        	
            
            if (pValue != NULL &&  PyBool_Check(pValue)) {
            	is_trusted = PyObject_IsTrue(pValue);
                printf("Result of call: %d\n",is_trusted);
                Py_DECREF(pValue);
                
            }
            else {
                //Py_DECREF(pFunc);
                Py_DECREF(pModule);
                PyErr_Print();
                fprintf(stderr,"Call failed\n");
                return 0;
            }
//        }
//        else {
//            if (PyErr_Occurred())
//                PyErr_Print();
//            fprintf(stderr, "Cannot find function \"%s\"\n", method);
//        }
        //Py_XDECREF(pFunc);
        Py_DECREF(pModule);
    }
    else {
        PyErr_Print();
        fprintf(stderr, "Failed to load \"%s\"\n", WEBID_MODULE);
        return 0;
    }
    Py_Finalize();
    return is_trusted;
}

int main(){
	int ret_value = trust("http://localhost:3000/fixtures/foaf/authorization_direct.rdf", 
			"http://localhost:3000/fixtures/foaf/supplicant_direct.rdf", WEBID_DIRECT_METHOD);
	
	printf("the value returned is: %d",ret_value);
	
	return 0;
}