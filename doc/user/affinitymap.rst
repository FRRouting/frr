.. _affinity-map:

*************
Affinity Maps
*************

Affinity maps provide a means of configuring Standard Admininistrative-Group
(RFC3630, RFC5305 and RFC5329) and Extended Admininistrative-Group (RFC7308).
An affinity-map maps a specific bit position to a human readable-name.

An affinity refers to a color or a ressource class in the Traffic Engineering
terminology. The bit position means the position of the bit set starting from
the least significant bit. For example, if the affinity 'blue' has bit position
0 the extended Admin-Group value will be 0x01. If the affinity 'red' bit
position 2 was added to a link in combination with the 'blue' affinity, the
Admin-Group value would be 0x05.

Command
-------

.. clicmd:: affinity-map NAME bit-position (0-1023)

   Map the affinity name NAME to the bit-position. The bit-position is the key
   so that only one name can be mapped to particular bit-position.

.. clicmd:: no affinity-map NAME

   Remove the affinity-map mapping.

Affinity-maps with a bit-position value higher than 31 are not compatible with
Standard Admininistrative-Group. The CLI disallow the usage of such
affinity-maps when Standard Admininistrative-Groups are required.