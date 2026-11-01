.. _ai-policy:

*************
AI/LLM policy
*************

.. highlight:: none


Terminology
===========

"AI" here refers primarily to Large Language Models, capable of generating code
or natural language from instructions ("prompts"), as well as autonomously
acting systems ("agentic" AI, "Claw" style setups) executing these functions
on their own initiative.

Explicitly not included are machine translation from one natural language to
another, code completion and templating systems.


Clear-cut cases
===============

"Agentic" AI
------------

Autonomously acting AI systems are not permitted to interact with the FRRouting
community in any manner.  In particular, opening GitHub issues or pull
requests by such systems is forbidden and may result in a ban.


Community Interactions
----------------------

The use of any AI tooling in interactions with other developers (Github
PR/Issue comments, Slack, e-mail lists, etc.) is strictly forbidden and may
result in a ban.


Security research/auditing
--------------------------

The use of AI tooling for security research/auditing is permitted, but must be
disclosed.  Any findings must be reviewed by a human before submission to the
FRRouting security contacts.  The community interaction rule (see previous
paragraph) still applies to security reports, i.e. as a researcher you are
expected to write the report yourself.

(Rationale: forbidding security research by AI is akin to sticking your head in
the sand and pretending the world around you is not on fire.  The research
happens either way, the alternative is for issues to go undiscovered and become
weaponized.)


Ambivalent cases
================

Changeset/PR authoring with AI assistance
-----------------------------------------

The use of AI tooling in the creation of code changes to FRRouting is, for the
time being, not forbidden but **strongly discouraged**, except for the use in
build-time-only components (primarily tests).

The use of AI tooling in the generation of changes can serve as a sufficient
reason for rejecting that change, at the discretion of FRRouting maintainers.
Large/bulk changes are more likely to receive this treatment.

(Rationale: as with most FOSS projects, our bottleneck is not people writing
code, it is review.  Having AI-generated code be reviewed by AI is rather
pointless, making this essentially into a binary choice: AI code or AI review.
We have decided for the latter.)


Attribution and Indemnification
-------------------------------

All code submitted/incorporated to FRRouting is attributed to the human author
and/or their employing company.  AI tools are not "valid targets" to attribute
something to, since they can't take responsibility.  Please also refer to the
:ref:`Developer's Certificate of Origin <developers-certificate-of-origin>` and
its implications.

Commit taglines such as ``Co-authored-by: AI tool <address@ai-corp.example>``
are considered advertisements, therefore not welcome and must be removed before
submission.  AI disclosure happens in the GitHub PR description.

**The attribution of code to a human author and/or their employing company also
implies that you are taking responsibility for the submission in a legal sense.
The copyright status of AI-generated code is not settled at the point of
creation of this policy.  It is your decision as an author/company to employ AI
tooling in knowledge of this fact.  You are assumed to be indemnifying the
FRRouting community and users against possible legal fallout from your use of
AI, as is already the case with code written by humans.**


Review tooling
--------------

The use of review tooling in the FRRouting community is permitted, but this is
expected to be a community-controlled process either way.  Comments raised by
AI tooling are defined to always be non-blocking.  In raising a blocker based
on some AI review output, you are taking responsibility for that item and in
particular its correctness.
