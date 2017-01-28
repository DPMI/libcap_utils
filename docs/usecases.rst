Use-cases
=========

Save a live MP stream to local file
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

   capdump -i eth0 -o trace.cap 01::10

Show contents of a saved trace
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

   capshow trace.cap


Show the content of two live streams
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

   capshow -i eth0 01::10 01::01
    
    
Merge two traces to a single file
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

   capmerge -o merged.cap trace1.cap trace2.cap
