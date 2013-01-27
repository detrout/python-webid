/*
 * gcc webid_trust.c  -Xlinker -export-dynamic -Wl,-O1 -Wl,-Bsymbolic-functions -I/usr/include/python2.7 -lpython2.7 -o trust

 * */


#include <Python.h>
#include "webid_trust.h"
#include <stdio.h>


int
trust(const char* auth_uri, const char* san_uri, char* method)
{
    PyObject  *pModule;
    PyObject *pValue;
    int  is_trusted = 0;



    Py_Initialize();

    pModule = PyImport_ImportModule(WEBID_MODULE);

    if (pModule != NULL) {
        	

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
	int ret_value = trust("https://my-profile.eu/people/ertan/card#me",
			"https://my-profile.eu/people/yunus/card#me", WEBID_DIRECT_METHOD);
	
	printf("the value returned is: %d",ret_value);
	
	return 0;
}
