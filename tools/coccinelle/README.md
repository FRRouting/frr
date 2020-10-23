Coccinelle patches
==================

This collection of coccinelle patches represents some of the broader,
codebase-wide changes that have been made. If you maintain a fork of
FRR and find that your codebase needs to be updated to align with
these changes, the coccinelle tool should help you make that update.

The coccinelle tool is documented at:
    https://coccinelle.gitlabpages.inria.fr/website/

To run a coccinelle patch script:

    spatch --sp-file tools/coccinelle/semicolon.cocci zebra/*.c
