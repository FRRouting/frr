/* Ethernet-VPN Attribute handling file
   Copyright (C) 2016 6WIND

This file is part of Free Range Routing.

Free Range Routing is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

Free Range Routing is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with Free Range Routing; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

#include <zebra.h>

#include "command.h"
#include "filter.h"
#include "prefix.h"
#include "log.h"
#include "memory.h"
#include "stream.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr_evpn.h"
#include "bgpd/bgp_ecommunity.h"

void bgp_add_routermac_ecom (struct attr* attr, char * routermac)
{
  struct ecommunity_val routermac_ecom;

  if(attr->extra)
    {
      memset(&routermac_ecom, 0, sizeof(struct ecommunity_val));
      routermac_ecom.val[0] = ECOMMUNITY_ENCODE_EVPN;
      routermac_ecom.val[1] = ECOMMUNITY_EVPN_SUBTYPE_ROUTERMAC;
      memcpy(&routermac_ecom.val[2], routermac, MAC_LEN);
      if(!attr->extra->ecommunity)
        attr->extra->ecommunity = ecommunity_new ();
      ecommunity_add_val(attr->extra->ecommunity, &routermac_ecom);
    }
}

static uint8_t convertchartohexa (uint8_t *hexa, int *error)
{
  if( (*hexa == '0') || (*hexa == '1') || (*hexa == '2') ||
      (*hexa == '3') || (*hexa == '4') || (*hexa == '5') ||
      (*hexa == '6') || (*hexa == '7') || (*hexa == '8') ||
      (*hexa == '9'))
    return (uint8_t)(*hexa)-'0';
  if((*hexa == 'a') || (*hexa == 'A'))
    return 0xa;
  if((*hexa == 'b') || (*hexa == 'B'))
    return 0xb;
  if((*hexa == 'c') || (*hexa == 'C'))
    return 0xc;
  if((*hexa == 'd') || (*hexa == 'D'))
    return 0xd;
  if((*hexa == 'e') || (*hexa == 'E'))
    return 0xe;
  if((*hexa == 'f') || (*hexa == 'F'))
    return 0xf;
  *error = -1;
  return 0;
}

/* converts to internal representation of mac address
 * returns 1 on success, 0 otherwise 
 * format accepted: AA:BB:CC:DD:EE:FF
 * if mac parameter is null, then check only
 */
int
str2mac (const char *str, char *mac)
{
  unsigned int k=0, i, j;
  uint8_t *ptr, *ptr2;
  size_t len;
  uint8_t car;

  if (!str)
    return 0;

  if (str[0] == ':' && str[1] == '\0')
    return 1;

  i = 0;
  ptr = (uint8_t *)str;
  while (i < 6)
    {
      uint8_t temp[5];
      int error = 0;
      ptr2 = (uint8_t *)strchr((const char *)ptr, ':');
      if (ptr2 == NULL)
	{
	  /* if last occurence return ok */
	  if(i != 5)
            {
              zlog_err("[%s]: format non recognized",mac);
              return 0;
            }
          len = strlen((char *)ptr);
	} 
      else
        {
          len = ptr2 - ptr;
        }
      if(len > 5)
        {
          zlog_err("[%s]: format non recognized",mac);
         return 0;
        }
      memcpy(temp, ptr, len);
      for(j=0;j< len;j++)
	{
	  if (k >= MAC_LEN)
	    return 0;
          if(mac)
            mac[k] = 0;
          car = convertchartohexa (&temp[j], &error);
	  if (error)
	    return 0;
	  if(mac)
            mac[k] = car << 4;
	  j++;
          if(j == len)
            return 0;
          car = convertchartohexa (&temp[j], &error) & 0xf;
	  if (error)
	    return 0;
	  if(mac)
            mac[k] |= car & 0xf;
	  k++;
	  i++;
	}
      ptr = ptr2;
      if(ptr == NULL)
        break;
      ptr++;
    }
  if(mac && 0)
    {
      zlog_err("leave correct : %02x:%02x:%02x:%02x:%02x:%02x",
               mac[0] & 0xff, mac[1] & 0xff, mac[2] & 0xff,
               mac[3] & 0xff, mac[4] & 0xff, mac[5] & 0xff);
    }
  return 1;
}

/* converts to an esi
 * returns 1 on success, 0 otherwise
 * format accepted: AA:BB:CC:DD:EE:FF:GG:HH:II:JJ
 * if id is null, check only is done
 */
int
str2esi (const char *str, struct eth_segment_id *id)
{
  unsigned int k=0, i, j;
  uint8_t *ptr, *ptr2;
  size_t len;
  uint8_t car;

  if (!str)
    return 0;
  if (str[0] == ':' && str[1] == '\0')
    return 1;

  i = 0;
  ptr = (uint8_t *)str;
  while (i < 10)
    {
      uint8_t temp[5];
      int error = 0;
      ptr2 = (uint8_t *)strchr((const char *)ptr, ':');
      if (ptr2 == NULL)
	{
	  /* if last occurence return ok */
	  if(i != 9)
            {
              zlog_err("[%s]: format non recognized",str);
              return 0;
            }
          len = strlen((char *)ptr);
	}
      else
        {
          len = ptr2 - ptr;
        }
      memcpy(temp, ptr, len);
      if(len > 5)
        {
          zlog_err("[%s]: format non recognized",str);
         return 0;
        }
      for(j=0;j< len;j++)
	{
	  if (k >= ESI_LEN)
	    return 0;
          if(id)
            id->val[k] = 0;
          car = convertchartohexa (&temp[j], &error);
          if (error)
            return 0;
          if(id)
            id->val[k] = car << 4;
          j++;
          if(j == len)
            return 0;
          car = convertchartohexa (&temp[j], &error) & 0xf;
          if (error)
            return 0;
          if(id)
            id->val[k] |= car & 0xf;
         k++;
         i++;
	}
      ptr = ptr2;
      if(ptr == NULL)
        break;
      ptr++;
    }
  if(id && 0)
    {
      zlog_err("leave correct : %02x:%02x:%02x:%02x:%02x",
               id->val[0], id->val[1], id->val[2], id->val[3], id->val[4]);
      zlog_err("%02x:%02x:%02x:%02x:%02x",
               id->val[5], id->val[6], id->val[7], id->val[8], id->val[9]);
    }
  return 1;
}

char *
esi2str (struct eth_segment_id *id)
{
  char *ptr;
  u_char *val;

  if(!id)
    return NULL;

  val = id->val;
  ptr = (char *) malloc ((ESI_LEN*2+ESI_LEN-1+1)*sizeof(char));

  snprintf (ptr, (ESI_LEN*2+ESI_LEN-1+1),
            "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
            val[0], val[1], val[2], val[3], val[4],
            val[5], val[6], val[7], val[8], val[9]);

  return ptr;
}

char *
mac2str (char *mac)
{
  char *ptr;

  if(!mac)
    return NULL;

  ptr = (char *) malloc ((MAC_LEN*2+MAC_LEN-1+1)*sizeof(char));

  snprintf (ptr, (MAC_LEN*2+MAC_LEN-1+1), "%02x:%02x:%02x:%02x:%02x:%02x",
           (uint8_t) mac[0], (uint8_t)mac[1], (uint8_t)mac[2], (uint8_t)mac[3],
           (uint8_t)mac[4], (uint8_t)mac[5]);

  return ptr;
}

char *ecom_mac2str(char *ecom_mac)
{
  char *en;

  en = ecom_mac;
  en+=2;
  return mac2str(en);
}
