/*
 * awe-mapper.c
 *
 * This file is part of the asynchronous ipc for xcap.
 * This file is responsible for providing mappings
 * between an integer identifier and a pointer to
 * an awe struct.
 *
 * Author: Michael Quigley
 * Date: January 2016 
 */

#include <linux/bug.h>
#include <lcd-domains/awe-mapper.h>
#define AWE_TABLE_COUNT 64

/*
 * NOTE: This implementation right now is just a ring buffer.
 * In the future, we probably want to change this to something
 * like a red black tree or a B-tree to account for differing
 * storage size requirements.
 */

static void* awe_table[AWE_TABLE_COUNT];
static uint32_t used_slots = 0;

//The address of this is used to indicate that something is
//allocated and not set to an awe_ptr yet.
static uint32_t allocated_marker = 0;



/*
 * Initilaizes awe mapper.
 */
void awe_mapper_init(void){/*Does nothing for now.*/}



/*
 * Uninitilaizes awe mapper.
 */
void awe_mapper_uninit(void){/*Does nothing for now.*/}



static bool is_slot_allocated(uint32_t id)
{
    return awe_table[id] != NULL;
}



/*
 * Returns new available id.
 */
uint32_t awe_mapper_create_id(void)
{
    static uint32_t next_id = 0;

    BUG_ON((used_slots >= AWE_TABLE_COUNT) && "Too many slots have been requested.");
    
    do
    {
        next_id = (next_id + 1) % AWE_TABLE_COUNT;
    } 
    while( is_slot_allocated(next_id) );

    awe_table[next_id] = &allocated_marker;

    used_slots++;

    return next_id;
}  
EXPORT_SYMBOL(awe_mapper_create_id);


/*
 * Marks provided id as available
 */
void awe_mapper_remove_id(uint32_t id)
{
    BUG_ON(id >= AWE_TABLE_COUNT);
    
    if(used_slots > 0)
    {
        used_slots--;
    }
    
    awe_table[id] = NULL;
}



/*
 * Links awe_ptr with id.
 */
void awe_mapper_set_id(uint32_t id, void* awe_ptr)
{
    BUG_ON(id >= AWE_TABLE_COUNT);
    awe_table[id] = awe_ptr;
}



/*
 * Returns awe_ptr that corresponds to id.
 */
void* awe_mapper_get_awe_ptr(uint32_t id)
{
    BUG_ON(id >= AWE_TABLE_COUNT);

    return awe_table[id];
}


