#' @title Update a credential item
#' 
#' @description In case an already existing credential item changes, this
#'              function may be used to modify its stored representation.
#'
#' @param item A credential item to be modified.
#'
#' @return NULL (invisibly).
#' 
#' @export
updateItem <- function(item) {
  UseMethod("updateItem", item)
}
#' @export
updateItem.LoginItem <- function(item) {
  return(updateFileBased(item))
}
#' @export
updateItem.default <- function(item) {
  stop("function not implemented for objects of class ",
       paste(class(item), collapse = ", "))
}
