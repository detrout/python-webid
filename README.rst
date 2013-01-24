python-webid
============

A python lib implementing server-side validation 
and client ssl authentication following the WebID spec
+ 
Now there is also support for Authorization
Direct and transitive trust has been checked. 
Use authorizer module.


reading the docs
================

Documentation `at RTD <http://readthedocs.org/docs/python-webid/en/latest/>`_
  

hacking together
================

  git clone git://github.com/yunus/python-webid.git

+ send patch / pull request ;)

for devs
========

- For authorization a separate testing suite is added. Goto src/test run>> python runtest.py . But before running the tests 
also run a simple http server@3000 (python -m SimpleHTTPServer 3000) under test directory to serve foaf fixtures. 

- Mailing lists on `foaf-protocols <http://lists.foaf-project.org/mailman/listinfo/foaf-protocols>`_
`W3C WebID Community Group <http://www.w3.org/community/webid/>`_

- `Current Spec <http://www.w3.org/2005/Incubator/webid/spec/>`_

- `WebID Test Suite <http://www.w3.org/2005/Incubator/webid/wiki/Test_Suite>`_

- To get an idea of how an implementation report should look like, `see this <http://www.w3.org/2001/sw/DataAccess/impl-report-ql>`_
