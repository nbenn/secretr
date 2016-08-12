#' @title Store a credential item
#' 
#' @description In order to store credential items, OS resources (such as the
#'              Mac OS Keychain) are used when possible. As a fall-back option,
#'              a file-based storage option is available which encrypts
#'              sensitive information and saves the key to the user's
#'              .Rprofile.
#'
#' @param item A credential item to be stored.
#'
#' @return NULL (invisibly).
#' 
#' @export
storeItem <- function(item) {
  UseMethod("storeItem", item)
}
#' @export
storeItem.LoginItem <- function(item) {
  return(storeFileBased(item))
}
#' @export
storeItem.default <- function(item) {
  stop("function not implemented for objects of class ",
       paste(class(item), collapse = ", "))
}
