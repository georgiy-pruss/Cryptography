/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */
/*  MTL website JavaScript functions (c) Chris Veness 2008-2009                                   */
/* - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -  */

/*
$(document).ready( function()  // jQuery onload initialisation
{
  // set external links to 'target=_blank'
  $('a[href^="http://"],a[href^="https://"]').attr("target","_blank");
});
*/

/* extend String object with trim method (if not built in)
 *   note efficient formulation from blog.stevenlevithan.com
 */
if(typeof(String.prototype.trim) === "undefined")
{
  String.prototype.trim = function()
  {
    return String(this).replace(/^\s\s*/, '').replace(/\s\s*$/, '');
  }
}

/* add isNumber function (if not built in)
 *   JavaScript: The Good Parts, Douglas Crockford, O'Reilly
 */
if(typeof(isNumber) === "undefined")
{
  var isNumber = function isNumber(value)
  {
    return typeof value === 'number' && isFinite(value);
  };
}
