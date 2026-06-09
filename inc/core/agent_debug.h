#ifndef AGENT_DEBUG_H
#define AGENT_DEBUG_H

/* Hot-path counters only; periodic flush to .cursor/debug-dfdcf7.log */
void ne_dbg_inc(const char *hypothesis_id);
void ne_agent_debug_flush_tick(unsigned tick);

#endif
