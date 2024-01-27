Demos
=====

Transactional CLI
-----------------

This short demo shows some of the capabilities of the new transactional
CLI:

|asciicast1|

ConfD + NETCONF + Cisco YDK
---------------------------

This is a very simple demo of *ripd* being configured by a python
script. The script uses NETCONF to communicate with *ripd*, which has
the ConfD plugin loaded. The most interesting part, however, is the fact
that the python script is not using handcrafted XML payloads to
configure *ripd*. Instead, the script is using python bindings generated
using Cisco’s YANG Development Kit (YDK).

-  Script used in the demo:
   https://gist.github.com/rwestphal/defa9bd1ccf216ab082d4711ae402f95

|asciicast2|

.. |asciicast1| image:: https://asciinema.org/a/jL0BS5HfP2kS6N1HfgsZvfZk1.png
   :target: https://asciinema.org/a/jL0BS5HfP2kS6N1HfgsZvfZk1
.. |asciicast2| image:: https://asciinema.org/a/VfMElNxsjLcdvV7484E6ChxWv.png
   :target: https://asciinema.org/a/VfMElNxsjLcdvV7484E6ChxWv
