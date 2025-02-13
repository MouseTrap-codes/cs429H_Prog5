/*
################################################################################
#  THIS FILE IS 100% GENERATED BY ZPROJECT; DO NOT EDIT EXCEPT EXPERIMENTALLY  #
#  Read the zproject/README.md for information about making permanent changes. #
################################################################################
*/

#include "QmlZlistx.h"


///
//  Add an item to the head of the list. Calls the item duplicator, if any,
//  on the item. Resets cursor to list head. Returns an item handle on
//  success.
void *QmlZlistx::addStart (void *item) {
    return zlistx_add_start (self, item);
};

///
//  Add an item to the tail of the list. Calls the item duplicator, if any,
//  on the item. Resets cursor to list head. Returns an item handle on
//  success.
void *QmlZlistx::addEnd (void *item) {
    return zlistx_add_end (self, item);
};

///
//  Return the number of items in the list
size_t QmlZlistx::size () {
    return zlistx_size (self);
};

///
//  Return first item in the list, or null, leaves the cursor
void *QmlZlistx::head () {
    return zlistx_head (self);
};

///
//  Return last item in the list, or null, leaves the cursor
void *QmlZlistx::tail () {
    return zlistx_tail (self);
};

///
//  Return the item at the head of list. If the list is empty, returns NULL.
//  Leaves cursor pointing at the head item, or NULL if the list is empty.
void *QmlZlistx::first () {
    return zlistx_first (self);
};

///
//  Return the next item. At the end of the list (or in an empty list),
//  returns NULL. Use repeated zlistx_next () calls to work through the list
//  from zlistx_first (). First time, acts as zlistx_first().
void *QmlZlistx::next () {
    return zlistx_next (self);
};

///
//  Return the previous item. At the start of the list (or in an empty list),
//  returns NULL. Use repeated zlistx_prev () calls to work through the list
//  backwards from zlistx_last (). First time, acts as zlistx_last().
void *QmlZlistx::prev () {
    return zlistx_prev (self);
};

///
//  Return the item at the tail of list. If the list is empty, returns NULL.
//  Leaves cursor pointing at the tail item, or NULL if the list is empty.
void *QmlZlistx::last () {
    return zlistx_last (self);
};

///
//  Returns the value of the item at the cursor, or NULL if the cursor is
//  not pointing to an item.
void *QmlZlistx::item () {
    return zlistx_item (self);
};

///
//  Returns the handle of the item at the cursor, or NULL if the cursor is
//  not pointing to an item.
void *QmlZlistx::cursor () {
    return zlistx_cursor (self);
};

///
//  Find an item in the list, searching from the start. Uses the item
//  comparator, if any, else compares item values directly. Returns the
//  item handle found, or NULL. Sets the cursor to the found item, if any.
void *QmlZlistx::find (void *item) {
    return zlistx_find (self, item);
};

///
//  Detach an item from the list, using its handle. The item is not modified,
//  and the caller is responsible for destroying it if necessary. If handle is
//  null, detaches the first item on the list. Returns item that was detached,
//  or null if none was. If cursor was at item, moves cursor to previous item,
//  so you can detach items while iterating forwards through a list.
void *QmlZlistx::detach (void *handle) {
    return zlistx_detach (self, handle);
};

///
//  Detach item at the cursor, if any, from the list. The item is not modified,
//  and the caller is responsible for destroying it as necessary. Returns item
//  that was detached, or null if none was. Moves cursor to previous item, so
//  you can detach items while iterating forwards through a list.
void *QmlZlistx::detachCur () {
    return zlistx_detach_cur (self);
};

///
//  Delete an item, using its handle. Calls the item destructor if any is
//  set. If handle is null, deletes the first item on the list. Returns 0
//  if an item was deleted, -1 if not. If cursor was at item, moves cursor
//  to previous item, so you can delete items while iterating forwards
//  through a list.
int QmlZlistx::delete (void *handle) {
    return zlistx_delete (self, handle);
};

///
//  Move an item to the start of the list, via its handle.
void QmlZlistx::moveStart (void *handle) {
    zlistx_move_start (self, handle);
};

///
//  Move an item to the end of the list, via its handle.
void QmlZlistx::moveEnd (void *handle) {
    zlistx_move_end (self, handle);
};

///
//  Remove all items from the list, and destroy them if the item destructor
//  is set.
void QmlZlistx::purge () {
    zlistx_purge (self);
};

///
//  Sort the list. If an item comparator was set, calls that to compare
//  items, otherwise compares on item value. The sort is not stable, so may
//  reorder equal items.
void QmlZlistx::sort () {
    zlistx_sort (self);
};

///
//  Create a new node and insert it into a sorted list. Calls the item
//  duplicator, if any, on the item. If low_value is true, starts searching
//  from the start of the list, otherwise searches from the end. Use the item
//  comparator, if any, to find where to place the new node. Returns a handle
//  to the new node. Resets the cursor to the list head.
void *QmlZlistx::insert (void *item, bool lowValue) {
    return zlistx_insert (self, item, lowValue);
};

///
//  Move an item, specified by handle, into position in a sorted list. Uses
//  the item comparator, if any, to determine the new location. If low_value
//  is true, starts searching from the start of the list, otherwise searches
//  from the end.
void QmlZlistx::reorder (void *handle, bool lowValue) {
    zlistx_reorder (self, handle, lowValue);
};

///
//  Make a copy of the list; items are duplicated if you set a duplicator
//  for the list, otherwise not. Copying a null reference returns a null
//  reference.
QmlZlistx *QmlZlistx::dup () {
    QmlZlistx *retQ_ = new QmlZlistx ();
    retQ_->self = zlistx_dup (self);
    return retQ_;
};

///
//  Set a user-defined deallocator for list items; by default items are not
//  freed when the list is destroyed.
void QmlZlistx::setDestructor (zlistx_destructor_fn destructor) {
    zlistx_set_destructor (self, destructor);
};

///
//  Set a user-defined duplicator for list items; by default items are not
//  copied when the list is duplicated.
void QmlZlistx::setDuplicator (zlistx_duplicator_fn duplicator) {
    zlistx_set_duplicator (self, duplicator);
};

///
//  Set a user-defined comparator for zlistx_find and zlistx_sort; the method
//  must return -1, 0, or 1 depending on whether item1 is less than, equal to,
//  or greater than, item2.
void QmlZlistx::setComparator (zlistx_comparator_fn comparator) {
    zlistx_set_comparator (self, comparator);
};

///
//  Serialize list to a binary frame that can be sent in a message.
//  The packed format is compatible with the 'strings' type implemented by zproto:
//
//     ; A list of strings
//     list            = list-count *longstr
//     list-count      = number-4
//
//     ; Strings are always length + text contents
//     longstr         = number-4 *VCHAR
//
//     ; Numbers are unsigned integers in network byte order
//     number-4        = 4OCTET
QmlZframe *QmlZlistx::pack () {
    QmlZframe *retQ_ = new QmlZframe ();
    retQ_->self = zlistx_pack (self);
    return retQ_;
};


QObject* QmlZlistx::qmlAttachedProperties(QObject* object) {
    return new QmlZlistxAttached(object);
}


///
//  Returns the item associated with the given list handle, or NULL if passed
//  in handle is NULL. Asserts that the passed in handle points to a list element.
void *QmlZlistxAttached::handleItem (void *handle) {
    return zlistx_handle_item (handle);
};

///
//  Self test of this class.
void QmlZlistxAttached::test (bool verbose) {
    zlistx_test (verbose);
};

///
//  Create a new, empty list.
QmlZlistx *QmlZlistxAttached::construct () {
    QmlZlistx *qmlSelf = new QmlZlistx ();
    qmlSelf->self = zlistx_new ();
    return qmlSelf;
};

///
//  Unpack binary frame into a new list. Packed data must follow format
//  defined by zlistx_pack. List is set to autofree. An empty frame
//  unpacks to an empty list.
QmlZlistx *QmlZlistxAttached::unpack (QmlZframe *frame) {
    QmlZlistx *qmlSelf = new QmlZlistx ();
    qmlSelf->self = zlistx_unpack (frame->self);
    return qmlSelf;
};

///
//  Destroy a list. If an item destructor was specified, all items in the
//  list are automatically destroyed as well.
void QmlZlistxAttached::destruct (QmlZlistx *qmlSelf) {
    zlistx_destroy (&qmlSelf->self);
};

/*
################################################################################
#  THIS FILE IS 100% GENERATED BY ZPROJECT; DO NOT EDIT EXCEPT EXPERIMENTALLY  #
#  Read the zproject/README.md for information about making permanent changes. #
################################################################################
*/
