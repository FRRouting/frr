/* special styling for the protocols vs. OS table in overview.rst
 *
 * unfortunately this can't be done in straight CSS because we're changing
 * the styling on the parent.
 */
$(document).ready(function() {
    $("span.mark:contains('Y')" ).addClass("mark-y"  ).parent("td").addClass("mark");
    $("span.mark:contains('≥')" ).addClass("mark-geq").parent("td").addClass("mark");
    $("span.mark:contains('N')" ).addClass("mark-n"  ).parent("td").addClass("mark");
    $("span.mark:contains('CP')").addClass("mark-cp" ).parent("td").addClass("mark");
    $("span.mark:contains('†')" ).addClass("mark-dag").parent("td").addClass("mark");
    $('td.mark').parents('table').addClass("mark").children('colgroup').remove();
});
