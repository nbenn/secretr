#' @title Create a LoginItem object
#' 
#' @description A LoginItem object is created from a service name (which
#'              is used to identify the credential item), a user name and
#'              (optionally) a password. If the password is not supplied, a
#'              new one is generated using generatePassword.
#'
#' @param service  The name, by which the LoginItem object is identified.
#' @param username A string, specifying the user name.
#' @param password NULL or a string specifying the password.
#'
#' @return A LoginItem object, which is a list containing entries
#'         service, username, password and encrypted (logical).
#' 
#' @export
LoginItem <- function(service, username, password = NULL) {
  stopifnot(
    is.character(service), length(service) == 1, nchar(service) > 0,
    is.character(username), length(username) == 1, nchar(username) > 0)
  if (is.null(password)) password <- generatePassword()
  else {
    stopifnot(is.character(password), length(password) == 1,
              nchar(username) > 0)
  }
  return(structure(list(
    service = service,
    username = username,
    password = password,
    encrypted = FALSE), class = "LoginItem"))
}

#' @title Get the ID of an Item
#' 
#' @description The ID of each Item is used as a unique identifier.
#'
#' @param item A credential item to be identified.
#'
#' @return The ID of the supplied item.
#' 
#' @export
getItemId <- function(item) {
  UseMethod("getItemId", item)
}
#' @export
getItemId.LoginItem <- function(item) {
  return(item$service)
}
#' @export
getItemId.default <- function(item) {
  stop("function not implemented for objects of class ",
       paste(class(item), collapse = ", "))
}