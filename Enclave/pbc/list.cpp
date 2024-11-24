#include <stdlib.h>
#include <string.h>
#include "list.h"
#include "c_pre.h"
#include "../Enclave.h"
#include "../Enclave_t.h" /* print_string */

/* Creates a list (node) and returns it
 * Arguments: The data the list will contain or NULL to create an empty
 * list/node
 */
list_node* list_create(void *data)
{
	list_node *l = (list_node *)malloc(sizeof(list_node));
	if (l != NULL) {
		l->next = NULL;
		l->data = data;
	}

	return l;
}

/* Completely destroys a list
 * Arguments: A pointer to a pointer to a list
 */
void list_destroy(list_node **list)
{
	if (list == NULL) return;
	while (*list != NULL) {
		list_remove(list, *list);
	}
}

/* Creates a list node and inserts it after the specified node
 * Arguments: A node to insert after and the data the new node will contain
 */
list_node* list_insert_after(list_node *node, void *data)
{
	list_node *new_node = list_create(data);
	if (new_node) {
		new_node->next = node->next;
		node->next = new_node;
	}
	return new_node;
}

/* Creates a new list node and inserts it in the beginning of the list
 * Arguments: The list the node will be inserted to and the data the node will
 * contain
 */
list_node* list_insert_beginning(list_node *list, void *data)
{
	list_node *new_node = list_create(data);
	if (new_node != NULL) { new_node->next = list; }
	return new_node;
}

/* Creates a new list node and inserts it at the end of the list
 * Arguments: The list the node will be inserted to and the data the node will
 * contain
 */
list_node* list_insert_end(list_node *list, void *data)
{
	list_node *new_node = list_create(data);
	if (new_node != NULL) {
		for(list_node *it = list; it != NULL; it = it->next) {
			if (it->next == NULL) {
				it->next = new_node;
				break;
			}
		}
	}
	return new_node;
}

/* Removes a node from the list
 * Arguments: The list and the node that will be removed
 */
void list_remove(list_node **list, list_node *node)
{
	list_node *tmp = NULL;
	if (list == NULL || *list == NULL || node == NULL) return;

	if (*list == node) {
		*list = (*list)->next;
		free(node);
		node = NULL;
	} else {
		tmp = *list;
		while (tmp->next && tmp->next != node) tmp = tmp->next;
		if (tmp->next) {
			tmp->next = node->next;
			free(node);
			node = NULL;
		}
	}
}

/* Removes an element from a list by comparing the data pointers
 * Arguments: A pointer to a pointer to a list and the pointer to the data
 */
void list_remove_by_data(list_node **list, void *data)
{
	if (list == NULL || *list == NULL || data == NULL) return;
	list_remove(list, list_find_by_data(*list, data));
}

/* Find an element in a list by the pointer to the element
 * Arguments: A pointer to a list and a pointer to the node/element
 */
list_node* list_find_node(list_node *list, list_node *node)
{
	while (list) {
		if (list == node) break;
		list = list->next;
	}
	return list;
}

/* Finds an elemt in a list by the data pointer
 * Arguments: A pointer to a list and a pointer to the data
 */
int compare_by_data(ShareFile_t *data1, ShareFile_t *data2) 
{
    // return  (strcmp(data1->file_id, data2->file_id) == 0) &&
	// 		(strcmp(data1->Cert_owner_info_sign_value, 
	// 			data2->Cert_owner_info_sign_value) == 0) &&
	// 		(strcmp(data1->owner_grant_info_sign_value, 
	// 			data2->owner_grant_info_sign_value) == 0);
	return  (strcmp((const char*)(data1->share_id), (const char*)(data2->share_id)) == 0);
}
list_node* list_find_by_data(list_node *list, void *data)
{
	while (list) {
        if(compare_by_data( (ShareFile_t *)(list->data),
			(ShareFile_t *)data ))
            break;
		list = list->next;
	}
	return list;
}

// list_node* list_find_by_data(list_node *list, void *data)
// {
// 	while (list) {
// 		if (list->data == data) break;
// 		list = list->next;
// 	}
// 	return list;
// }

/* Finds an element in the list by using the comparison function
 * Arguments: A pointer to a list, the comparison function and a pointer to the
 * data
 */
int compare_ShareFile(list_node *list, void *data) 
{
	ShareFile_t *sf = (ShareFile_t *)(list->data);
	return  (strcmp((const char*)(sf->share_id), (const char*)((ShareFile_t *)data)->share_id) == 0);
}
list_node* list_find(list_node *list, int(*func)(list_node*,void*), void *data)
{
	if (!func) return NULL;
	while(list) {
		if (func(list, data)) break;
		list = list->next;
	}
	return list;
}

/* return the size of list
 * Arguments: A pointer to a pointer to a list
 */
int list_size(list_node **list)
{
	size_t size = 0;
	if (list == NULL) return size;
	list_node *tmp = *list;
	while (tmp != NULL) {
		tmp = tmp->next;
		size ++;
	}
	return size;
}

/* print the list
 * Arguments: A pointer to a pointer to a list
 */
void list_print(list_node **list)
{
	sgx_printf("list_print start, list = %p\n", list);
	if (list == NULL) return;
	list_node *tmp = *list;
	int index = 0;
	sgx_printf("list_print, tmp = %p\n", tmp);
	while (tmp != NULL) {
		ShareFile_t *sf = (ShareFile_t *)(tmp->data);
		sgx_printf("element %d:\n", index);
		sgx_printf("\tshare_id = %s\n\tfild_id = %s\n\tfile_name = %s\n", 
            sf->share_id, sf->file_id, sf->file_name);
		tmp = tmp->next;
		index ++;
	}
	sgx_printf("list_print end\n");
}