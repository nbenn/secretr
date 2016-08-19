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

#' @title Encrypt a credential item
#' 
#' @description Due to insecurity of file based credential storage, the
#'              sensitive information is encrypted.
#'
#' @param item A credential item to be encrypted.
#'
#' @return An encrypted credential item.
#' 
#' @export
encryptItem <- function(item) {
  UseMethod("encryptItem", item)
}
#' @export
encryptItem.LoginItem <- function(item) {
  if (item$encrypted) {
    warning("item already encrypted. doing nothing.")
    return(item)
  } else {
    if (!requireNamespace("openssl", quietly = TRUE)) {
      stop("could not find the package \"openssl\".")
    }
    fileBasedStorageSession()
    secretr_key <- getOption("secretr.key")
    secretr_key <- charToRaw(secretr_key)
    secretr_key <- openssl::sha256(secretr_key)
    if (length(secretr_key) != 32) {
      stop("cannot perform aes-256 due to key length != 32 bytes")
    }
    item$password <- openssl::aes_cbc_encrypt(charToRaw(item$password),
                                              key = secretr_key)
    item$encrypted <- TRUE
    return(item)
  }
}
#' @export
encryptItem.default <- function(item) {
  stop("function not implemented for objects of class ",
       paste(class(item), collapse = ", "))
}

#' @title Decrypt a credential item
#' 
#' @description Due to insecurity of file based credential storage, the
#'              sensitive information is encrypted.
#'
#' @param item A credential item to be decrypted.
#'
#' @return A decrypted credential item.
#' 
#' @export
decryptItem <- function(item) {
  UseMethod("decryptItem", item)
}
#' @export
decryptItem.LoginItem <- function(item) {
  if (!item$encrypted) {
    warning("item not encrypted. doing nothing.")
    return(item)
  } else {
    if (!requireNamespace("openssl", quietly = TRUE)) {
      stop("could not find the package \"openssl\".")
    }
    fileBasedStorageSession()
    secretr_key <- getOption("secretr.key")
    secretr_key <- charToRaw(secretr_key)
    secretr_key <- openssl::sha256(secretr_key)
    if (length(secretr_key) != 32) {
      stop("cannot perform aes-256 due to key length != 32 bytes")
    }
    raw <- openssl::aes_cbc_decrypt(item$password, key = secretr_key)
    item$password <- rawToChar(raw)
    item$encrypted <- FALSE
    return(item)
  }
}
#' @export
decryptItem.default <- function(item) {
  stop("function not implemented for objects of class ",
       paste(class(item), collapse = ", "))
}
