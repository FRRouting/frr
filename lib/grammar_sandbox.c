/*
 * Testing shim and API examples for the new CLI backend.
 *
 * This unit defines a number of commands in the old engine that can
 * be used to test and interact with the new engine.
 * --
 * Copyright (C) 2016 Cumulus Networks, Inc.
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include "command.h"
#include "memory_vty.h"
#include "graph.h"
#include "linklist.h"
#include "command_match.h"

#define GRAMMAR_STR "CLI grammar sandbox\n"

DEFINE_MTYPE_STATIC(LIB, CMD_TOKENS, "Command desc")

#define MAXDEPTH 64

/** headers **/
void
grammar_sandbox_init (void);
void
pretty_print_graph (struct vty *vty, struct graph_node *, int, int, struct graph_node **, size_t);
static void
pretty_print_dot (FILE *ofd, unsigned opts, struct graph_node *start,
                  struct graph_node **stack, size_t stackpos,
                  struct graph_node **visited, size_t *visitpos);
void
init_cmdgraph (struct vty *, struct graph **);

/** shim interface commands **/
struct graph *nodegraph = NULL, *nodegraph_free = NULL;

DEFUN (grammar_test,
       grammar_test_cmd,
       "grammar parse LINE...",
       GRAMMAR_STR
       "parse a command\n"
       "command to pass to new parser\n")
{
  int idx_command = 2;
  // make a string from tokenized command line
  char *command = argv_concat (argv, argc, idx_command);

  // create cmd_element for parser
  struct cmd_element *cmd = XCALLOC (MTYPE_CMD_TOKENS, sizeof (struct cmd_element));
  cmd->string = command;
  cmd->doc = "0\n1\n2\n3\n4\n5\n6\n7\n8\n9\n10\n11\n12\n13\n14\n15\n16\n17\n18\n19\n";
  cmd->func = NULL;

  // parse the command and install it into the command graph
  struct graph *graph = graph_new();
  struct cmd_token *token = new_cmd_token (START_TKN, CMD_ATTR_NORMAL, NULL, NULL);
  graph_new_node (graph, token, (void (*)(void *)) &del_cmd_token);

  command_parse_format (graph, cmd);
  cmd_merge_graphs (nodegraph, graph, +1);

  return CMD_SUCCESS;
}

DEFUN (grammar_test_complete,
       grammar_test_complete_cmd,
       "grammar complete COMMAND...",
       GRAMMAR_STR
       "attempt to complete input on DFA\n"
       "command to complete\n")
{
  int idx_command = 2;
  char *cmdstr = argv_concat (argv, argc, idx_command);
  if (!cmdstr)
    return CMD_SUCCESS;

  vector command = cmd_make_strvec (cmdstr);
  if (!command)
    {
      XFREE (MTYPE_TMP, cmdstr);
      return CMD_SUCCESS;
    }

  // generate completions of user input
  struct list *completions;
  enum matcher_rv result = command_complete (nodegraph, command, &completions);

  // print completions or relevant error message
  if (!MATCHER_ERROR(result))
    {
      vector comps = completions_to_vec (completions);
      struct cmd_token *tkn;

      // calculate length of longest tkn->text in completions
      unsigned int width = 0, i = 0;
      for (i = 0; i < vector_active (comps); i++) {
        tkn = vector_slot (comps, i);
        unsigned int len = strlen (tkn->text);
        width = len > width ? len : width;
      }

      // print completions
      for (i = 0; i < vector_active (comps); i++) {
        tkn = vector_slot (comps, i);
        vty_out (vty, "  %-*s  %s%s", width, tkn->text, tkn->desc, VTY_NEWLINE);
      }

      for (i = 0; i < vector_active (comps); i++)
        del_cmd_token ((struct cmd_token *) vector_slot (comps, i));
      vector_free (comps);
    }
  else
    vty_out (vty, "%% No match%s", VTY_NEWLINE);

  // free resources
  list_delete (completions);
  cmd_free_strvec (command);
  XFREE (MTYPE_TMP, cmdstr);

  return CMD_SUCCESS;
}

DEFUN (grammar_test_match,
       grammar_test_match_cmd,
       "grammar match COMMAND...",
       GRAMMAR_STR
       "attempt to match input on DFA\n"
       "command to match\n")
{
  int idx_command = 2;
  if (argv[2]->arg[0] == '#')
    return CMD_SUCCESS;

  char *cmdstr = argv_concat(argv, argc, idx_command);
  if (!cmdstr)
    return CMD_SUCCESS;
  vector command = cmd_make_strvec (cmdstr);
  if (!command)
    {
       XFREE (MTYPE_TMP, cmdstr);
       return CMD_SUCCESS;
    }

  struct list *argvv = NULL;
  const struct cmd_element *element = NULL;
  enum matcher_rv result = command_match (nodegraph, command, &argvv, &element);

  // print completions or relevant error message
  if (element)
    {
      vty_out (vty, "Matched: %s%s", element->string, VTY_NEWLINE);
      struct listnode *ln;
      struct cmd_token *token;
      for (ALL_LIST_ELEMENTS_RO(argvv,ln,token))
        vty_out (vty, "%s -- %s%s", token->text, token->arg, VTY_NEWLINE);

      vty_out (vty, "func: %p%s", element->func, VTY_NEWLINE);

      list_delete (argvv);
    }
  else {
     assert(MATCHER_ERROR(result));
     switch (result) {
       case MATCHER_NO_MATCH:
          vty_out (vty, "%% Unknown command%s", VTY_NEWLINE);
          break;
       case MATCHER_INCOMPLETE:
          vty_out (vty, "%% Incomplete command%s", VTY_NEWLINE);
          break;
       case MATCHER_AMBIGUOUS:
          vty_out (vty, "%% Ambiguous command%s", VTY_NEWLINE);
          break;
       default:
          vty_out (vty, "%% Unknown error%s", VTY_NEWLINE);
          break;
     }
  }

  // free resources
  cmd_free_strvec (command);
  XFREE (MTYPE_TMP, cmdstr);

  return CMD_SUCCESS;
}

/**
 * Testing shim to test docstrings
 */
DEFUN (grammar_test_doc,
       grammar_test_doc_cmd,
       "grammar test docstring",
       GRAMMAR_STR
       "Test function for docstring\n"
       "Command end\n")
{
  // create cmd_element with docstring
  struct cmd_element *cmd = XCALLOC (MTYPE_CMD_TOKENS, sizeof (struct cmd_element));
  cmd->string = XSTRDUP (MTYPE_CMD_TOKENS, "test docstring <example|selector follow> (1-255) end VARIABLE [OPTION|set lol] . VARARG");
  cmd->doc = XSTRDUP (MTYPE_CMD_TOKENS,
             "Test stuff\n"
             "docstring thing\n"
             "first example\n"
             "second example\n"
             "follow\n"
             "random range\n"
             "end thingy\n"
             "variable\n"
             "optional variable\n"
             "optional set\n"
             "optional lol\n"
             "vararg!\n");
  cmd->func = NULL;

  // parse element
  command_parse_format (nodegraph, cmd);

  return CMD_SUCCESS;
}

/**
 * Debugging command to print command graph
 */
DEFUN (grammar_test_show,
       grammar_test_show_cmd,
       "grammar show [doc]",
       GRAMMAR_STR
       "print current accumulated DFA\n"
       "include docstrings\n")
{
  struct graph_node *stack[MAXDEPTH];

  if (!nodegraph)
    vty_out(vty, "nodegraph uninitialized\r\n");
  else
    pretty_print_graph (vty, vector_slot (nodegraph->nodes, 0), 0, argc >= 3, stack, 0);
  return CMD_SUCCESS;
}

DEFUN (grammar_test_dot,
       grammar_test_dot_cmd,
       "grammar dotfile OUTNAME",
       GRAMMAR_STR
       "print current graph for dot\n"
       ".dot filename\n")
{
  struct graph_node *stack[MAXDEPTH];
  struct graph_node *visited[MAXDEPTH*MAXDEPTH];
  size_t vpos = 0;

  if (!nodegraph) {
    vty_out(vty, "nodegraph uninitialized\r\n");
    return CMD_SUCCESS;
  }
  FILE *ofd = fopen(argv[2]->arg, "w");
  if (!ofd) {
    vty_out(vty, "%s: %s\r\n", argv[2]->arg, strerror(errno));
    return CMD_SUCCESS;
  }

  fprintf(ofd, "digraph {\n  graph [ rankdir = LR ];\n  node [ fontname = \"Fira Mono\", fontsize = 9 ];\n\n");
  pretty_print_dot (ofd, 0,
                    vector_slot (nodegraph->nodes, 0),
                    stack, 0, visited, &vpos);
  fprintf(ofd, "}\n");
  fclose(ofd);
  return CMD_SUCCESS;
}

struct cmd_permute_item
{
  char *cmd;
  struct cmd_element *el;
};

static void
cmd_permute_free (void *arg)
{
  struct cmd_permute_item *i = arg;
  XFREE (MTYPE_TMP, i->cmd);
  XFREE (MTYPE_TMP, i);
}

static int
cmd_permute_cmp (void *a, void *b)
{
  struct cmd_permute_item *aa = a, *bb = b;
  return strcmp (aa->cmd, bb->cmd);
}

static void
cmd_graph_permute (struct list *out, struct graph_node **stack,
                   size_t stackpos, char *cmd)
{
  struct graph_node *gn = stack[stackpos];
  struct cmd_token *tok = gn->data;
  char *appendp = cmd + strlen(cmd);
  size_t i, j;

  if (tok->type < SPECIAL_TKN)
    {
      sprintf (appendp, "%s ", tok->text);
      appendp += strlen (appendp);
    }
  else if (tok->type == END_TKN)
    {
      struct cmd_permute_item *i = XMALLOC (MTYPE_TMP, sizeof (*i));
      i->el = ((struct graph_node *)vector_slot (gn->to, 0))->data;
      i->cmd = XSTRDUP (MTYPE_TMP, cmd);
      i->cmd[strlen(cmd) - 1] = '\0';
      listnode_add_sort (out, i);
      return;
    }

  if (++stackpos == MAXDEPTH)
    return;

  for (i = 0; i < vector_active (gn->to); i++)
    {
      struct graph_node *gnext = vector_slot (gn->to, i);
      for (j = 0; j < stackpos; j++)
        if (stack[j] == gnext)
          break;
      if (j != stackpos)
        continue;

      stack[stackpos] = gnext;
      *appendp = '\0';
      cmd_graph_permute (out, stack, stackpos, cmd);
    }
}

static struct list *
cmd_graph_permutations (struct graph *graph)
{
  char accumulate[2048] = "";
  struct graph_node *stack[MAXDEPTH];

  struct list *rv = list_new ();
  rv->cmp = cmd_permute_cmp;
  rv->del = cmd_permute_free;
  stack[0] = vector_slot (graph->nodes, 0);
  cmd_graph_permute (rv, stack, 0, accumulate);
  return rv;
}

extern vector cmdvec;

DEFUN (grammar_findambig,
       grammar_findambig_cmd,
       "grammar find-ambiguous [{printall|nodescan}]",
       GRAMMAR_STR
       "Find ambiguous commands\n"
       "Print all permutations\n"
       "Scan all nodes\n")
{
  struct list *commands;
  struct cmd_permute_item *prev = NULL, *cur = NULL;
  struct listnode *ln;
  int i, printall, scan, scannode = 0;
  int ambig = 0;

  i = 0;
  printall = argv_find (argv, argc, "printall", &i);
  i = 0;
  scan = argv_find (argv, argc, "nodescan", &i);

  if (scan && nodegraph_free)
    {
      graph_delete_graph (nodegraph_free);
      nodegraph_free = NULL;
    }

  if (!scan && !nodegraph)
    {
      vty_out(vty, "nodegraph uninitialized\r\n");
      return CMD_WARNING;
    }

  do {
    if (scan)
      {
        struct cmd_node *cnode = vector_slot (cmdvec, scannode++);
        if (!cnode)
          continue;
        nodegraph = cnode->cmdgraph;
        if (!nodegraph)
          continue;
        vty_out (vty, "scanning node %d%s", scannode - 1, VTY_NEWLINE);
      }

    commands = cmd_graph_permutations (nodegraph);
    prev = NULL;
    for (ALL_LIST_ELEMENTS_RO (commands, ln, cur))
      {
        int same = prev && !strcmp (prev->cmd, cur->cmd);
        if (printall && !same)
          vty_out (vty, "'%s' [%x]%s", cur->cmd, cur->el->daemon, VTY_NEWLINE);
        if (same)
          {
            vty_out (vty, "'%s' AMBIGUOUS:%s", cur->cmd, VTY_NEWLINE);
            vty_out (vty, "  %s%s   '%s'%s", prev->el->name, VTY_NEWLINE, prev->el->string, VTY_NEWLINE);
            vty_out (vty, "  %s%s   '%s'%s", cur->el->name,  VTY_NEWLINE, cur->el->string,  VTY_NEWLINE);
            vty_out (vty, "%s", VTY_NEWLINE);
            ambig++;
          }
        prev = cur;
      }
    list_delete (commands);

    vty_out (vty, "%s", VTY_NEWLINE);
  } while (scan && scannode < LINK_PARAMS_NODE);

  vty_out (vty, "%d ambiguous commands found.%s", ambig, VTY_NEWLINE);

  if (scan)
    nodegraph = NULL;
  return ambig == 0 ? CMD_SUCCESS : CMD_WARNING;
}

DEFUN (grammar_init_graph,
       grammar_init_graph_cmd,
       "grammar init",
       GRAMMAR_STR
       "(re)initialize graph\n")
{
  if (nodegraph_free)
    graph_delete_graph (nodegraph_free);
  nodegraph_free = NULL;

  init_cmdgraph (vty, &nodegraph);
  return CMD_SUCCESS;
}

DEFUN (grammar_access,
       grammar_access_cmd,
       "grammar access (0-65535)",
       GRAMMAR_STR
       "access node graph\n"
       "node number\n")
{
  if (nodegraph_free)
    graph_delete_graph (nodegraph_free);
  nodegraph_free = NULL;

  struct cmd_node *cnode;

  cnode = vector_slot (cmdvec, atoi (argv[2]->arg));
  if (!cnode)
    {
      vty_out (vty, "%% no such node%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  vty_out (vty, "node %d%s", (int)cnode->node, VTY_NEWLINE);
  nodegraph = cnode->cmdgraph;
  return CMD_SUCCESS;
}

/* this is called in vtysh.c to set up the testing shim */
void grammar_sandbox_init(void) {
  init_cmdgraph (NULL, &nodegraph);

  // install all enable elements
  install_element (ENABLE_NODE, &grammar_test_cmd);
  install_element (ENABLE_NODE, &grammar_test_show_cmd);
  install_element (ENABLE_NODE, &grammar_test_dot_cmd);
  install_element (ENABLE_NODE, &grammar_test_match_cmd);
  install_element (ENABLE_NODE, &grammar_test_complete_cmd);
  install_element (ENABLE_NODE, &grammar_test_doc_cmd);
  install_element (ENABLE_NODE, &grammar_findambig_cmd);
  install_element (ENABLE_NODE, &grammar_init_graph_cmd);
  install_element (ENABLE_NODE, &grammar_access_cmd);
}

#define item(x) { x, #x }
struct message tokennames[] = {
  item(WORD_TKN),         // words
  item(VARIABLE_TKN),     // almost anything
  item(RANGE_TKN),        // integer range
  item(IPV4_TKN),         // IPV4 addresses
  item(IPV4_PREFIX_TKN),  // IPV4 network prefixes
  item(IPV6_TKN),         // IPV6 prefixes
  item(IPV6_PREFIX_TKN),  // IPV6 network prefixes

  /* plumbing types */
  item(FORK_TKN),
  item(JOIN_TKN),
  item(START_TKN),        // first token in line
  item(END_TKN),          // last token in line
  { 0 }
};

/**
 * Pretty-prints a graph, assuming it is a tree.
 *
 * @param start the node to take as the root
 * @param level indent level for recursive calls, always pass 0
 */
void
pretty_print_graph (struct vty *vty, struct graph_node *start, int level,
                    int desc, struct graph_node **stack, size_t stackpos)
{
  // print this node
  char tokennum[32];
  struct cmd_token *tok = start->data;

  snprintf(tokennum, sizeof(tokennum), "%d?", tok->type);
  vty_out(vty, "%s", lookup_msg(tokennames, tok->type, NULL));
  if (tok->text)
    vty_out(vty, ":\"%s\"", tok->text);
  if (desc)
    vty_out(vty, " ?'%s'", tok->desc);
  vty_out(vty, " ");

  if (stackpos == MAXDEPTH)
    {
      vty_out(vty, " -aborting! (depth limit)%s", VTY_NEWLINE);
      return;
    }
  stack[stackpos++] = start;

  int numto = desc ? 2 : vector_active (start->to);
  if (numto)
    {
      if (numto > 1)
        vty_out(vty, "%s", VTY_NEWLINE);
      for (unsigned int i = 0; i < vector_active (start->to); i++)
        {
          struct graph_node *adj = vector_slot (start->to, i);
          // if we're listing multiple children, indent!
          if (numto > 1)
            for (int j = 0; j < level+1; j++)
              vty_out(vty, "    ");
          // if this node is a vararg, just print *
          if (adj == start)
            vty_out(vty, "*");
          else if (((struct cmd_token *)adj->data)->type == END_TKN)
            vty_out(vty, "--END%s", VTY_NEWLINE);
          else {
            size_t k;
            for (k = 0; k < stackpos; k++)
              if (stack[k] == adj) {
                vty_out(vty, "<<loop@%zu %s", k, VTY_NEWLINE);
                break;
              }
            if (k == stackpos)
              pretty_print_graph (vty, adj, numto > 1 ? level+1 : level, desc, stack, stackpos);
          }
       }
    }
  else
    vty_out(vty, "%s", VTY_NEWLINE);
}

static void
pretty_print_dot (FILE *ofd, unsigned opts, struct graph_node *start,
                  struct graph_node **stack, size_t stackpos,
                  struct graph_node **visited, size_t *visitpos)
{
  // print this node
  char tokennum[32];
  struct cmd_token *tok = start->data;
  const char *color;

  for (size_t i = 0; i < (*visitpos); i++)
    if (visited[i] == start)
      return;
  visited[(*visitpos)++] = start;
  if ((*visitpos) == MAXDEPTH*MAXDEPTH)
    return;

  snprintf(tokennum, sizeof(tokennum), "%d?", tok->type);
  fprintf(ofd, "  n%p [ shape=box, label=<", start);

  fprintf(ofd, "<b>%s</b>", lookup_msg(tokennames, tok->type, NULL));
  if (tok->attr == CMD_ATTR_DEPRECATED)
    fprintf(ofd, " (d)");
  else if (tok->attr == CMD_ATTR_HIDDEN)
    fprintf(ofd, " (h)");
  if (tok->text) {
    if (tok->type == WORD_TKN)
      fprintf(ofd, "<br/>\"<font color=\"#0055ff\" point-size=\"11\"><b>%s</b></font>\"", tok->text);
    else
      fprintf(ofd, "<br/>%s", tok->text);
  }
/*  if (desc)
    fprintf(ofd, " ?'%s'", tok->desc); */
  switch (tok->type) {
  case START_TKN:	color = "#ccffcc"; break;
  case FORK_TKN:	color = "#aaddff"; break;
  case JOIN_TKN:	color = "#ddaaff"; break;
  case WORD_TKN:	color = "#ffffff"; break;
  default:		color = "#ffffff"; break;
  }
  fprintf(ofd, ">, style = filled, fillcolor = \"%s\" ];\n", color);

  if (stackpos == MAXDEPTH)
    return;
  stack[stackpos++] = start;

  for (unsigned int i = 0; i < vector_active (start->to); i++)
    {
      struct graph_node *adj = vector_slot (start->to, i);
      // if this node is a vararg, just print *
      if (adj == start) {
        fprintf(ofd, "  n%p -> n%p;\n", start, start);
      } else if (((struct cmd_token *)adj->data)->type == END_TKN) {
        //struct cmd_token *et = adj->data;
        fprintf(ofd, "  n%p -> end%p;\n", start, adj);
        fprintf(ofd, "  end%p [ shape=box, label=<end>, style = filled, fillcolor = \"#ffddaa\" ];\n", adj);
      } else {
        fprintf(ofd, "  n%p -> n%p;\n", start, adj);
        size_t k;
        for (k = 0; k < stackpos; k++)
          if (stack[k] == adj)
            break;
        if (k == stackpos) {
          pretty_print_dot (ofd, opts, adj, stack, stackpos, visited, visitpos);
        }
      }
   }
}


/** stuff that should go in command.c + command.h */
void
init_cmdgraph (struct vty *vty, struct graph **graph)
{
  // initialize graph, add start noe
  *graph = graph_new ();
  nodegraph_free = *graph;
  struct cmd_token *token = new_cmd_token (START_TKN, 0, NULL, NULL);
  graph_new_node (*graph, token, (void (*)(void *)) &del_cmd_token);
  if (vty)
    vty_out (vty, "initialized graph%s", VTY_NEWLINE);
}
