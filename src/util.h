/*
 * MUSCLE SmartCard Development ( http://www.linuxnet.com )
 *
 * Copyright (C) 2000-2004
 *  David Corcoran <corcoran@linuxnet.com>
 *  Damien Sauveron <damien.sauveron@labri.fr>
 *  Ludovic Rousseau <ludovic.rousseau@free.fr>
 *  Paul Klissner <paul.klissner@sun.com>
 *  Michael Bender <michael.bender@sun.com>
 *
 * <NEED TO FIX KEYWORDS>
 */


#ifndef	__util_h__
#define	__util_h__

#ifdef __cplusplus
extern "C"
{
#endif                                  

#define LIST_INIT(hd)   	 (hd)->nx = (hd)->pv = (hd)
#define LIST_NEEDS_INIT(hd)      ((hd)->nx == NULL) || ((hd->pv = NULL))
#define LIST_EMPTY(hd)  	 ((hd)->nx == (hd))

#define LIST_INS_BEFORE(p1, p2)               \
 { (p1)->nx = (p2); (p1)->pv = (p2)->pv; (p2)->pv->nx = (p1); (p2)->pv = (p1); }

 #define LIST_INS_AFTER(p1, p2)               \
 { (p1)->pv = (p2); (p1)->nx = (p2)->nx; (p2)->nx->pv = (p1); (p2)->nx = (p1); }

#define LIST_INSERT_FIRST(p, hd)    LIST_INS_AFTER(p, hd) 
#define LIST_INSERT_LAST(p, hd)     LIST_INS_BEFORE(p, hd)
#define LIST_FIRST(hd) 		 ((hd)->nx != (hd) ? (hd)->nx : 0)
#define LIST_LAST(hd)  		 ((hd)->pv != (hd) ? (hd)->pv : 0)

#define LIST_FOREACH(iter, hd)                \
  for (iter = (hd)->nx; iter != (hd); iter = iter->nx) 

#define LIST_REMOVE(p)                        \
 { (p)->nx->pv = (p)->pv; (p)->pv->nx = (p)->nx; }

#define LIST_MV(old_hd, new_hd) {             \
        if (LIST_EMPTY(old_hd)) {             \
                LIST_INIT(new_hd);            \
        } else {                              \
                (new_hd)->nx = (old_hd)->nx;  \
                (new_hd)->pv = (old_hd)->pv;  \
                (new_hd)->pv->nx = (new_hd);  \
                (new_hd)->nx->pv = (new_hd);  \
                LIST_INIT(old_hd,nx,pv);      \
        }                                     \
}
#ifdef __cplusplus
extern "C"
}
#endif

#endif
