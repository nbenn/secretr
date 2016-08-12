#' @title Store a credential item in file-based storage
#' 
#' @description Write a credential item to file-based storage, in case no OS
#'              resource for storing credentials is available/implemented.
#'
#' @param item A credential item to be stored.
#'
#' @return NULL (invisibly).
#' 
storeFileBased <- function(item) {
  fileBasedStorageSession()
  secretr_path <- getOption("secretr.path")
  if (file.exists(secretr_path)) {
    vault <- readRDS(secretr_path)
    if (getItemId(item) %in% sapply(vault, getItemId)) {
      stop("the item to be stored is already present.")
    } else if (length(vault) == 0) {
      vault <- list(encryptItem(item))
    } else {
      vault[[length(vault) + 1]] <- encryptItem(item)
    }
  } else {
    vault <- list(encryptItem(item))
  }
  saveRDS(vault, secretr_path)
  return(invisible(NULL))
}

#' @title Update a credential item in file-based storage
#' 
#' @description In case an already existing credential item changes, this
#'              function may be used to modify its file-based storage
#'              representation.
#'
#' @param item A credential item to be modified.
#'
#' @return NULL (invisibly).
#' 
updateFileBased <- function(item) {
  fileBasedStorageSession()
  secretr_path <- getOption("secretr.path")
  if (!file.exists(secretr_path)) {
    stop("cannot find .Rsecrets file.")
  }
  vault <- readRDS(secretr_path)
  index <- grep(getItemId(item), sapply(vault, getItemId), fixed = TRUE)
  if (length(index) != 1) {
    stop("did not find 1, but ", length(index), " matches")
  }
  vault[[index]] <- encryptItem(item)
  saveRDS(vault, secretr_path)
  return(invisible(NULL))
}

#' @title Fetch a credential item from file-based storage
#' 
#' @description Fetches a credential item from secure file-based storage.
#'
#' @param id The ID of the requested credential item.
#'
#' @return The requested credential item.
#' 
fetchFileBased <- function(id) {
  fileBasedStorageSession()
  secretr_path <- getOption("secretr.path")
  if (!file.exists(secretr_path)) {
    stop("cannot find .Rsecrets file.")
  }
  vault <- readRDS(secretr_path)
  index <- grep(id, sapply(vault, getItemId), fixed = TRUE)
  if (length(index) != 1) {
    stop("did not find 1, but ", length(index), " matches")
  }
  return(decryptItem(vault[[index]]))
}

#' @title Delete a credential item from file-based storage
#' 
#' @description Remove a credential item from secure file-based storage.
#'
#' @param id The ID of the credential item to be deleted.
#'
#' @return NULL (invisibly).
#' 
removeFileBased <- function(id) {
  fileBasedStorageSession()
  secretr_path <- getOption("secretr.path")
  if (!file.exists(secretr_path)) {
    stop("cannot find .Rsecrets file.")
  }
  vault <- readRDS(secretr_path)
  index <- grep(id, sapply(vault, getItemId), fixed = TRUE)
  if (length(index) != 1) {
    stop("did not find 1, but ", length(index), " matches")
  }
  saveRDS(vault[-index], secretr_path)
  return(invisible(NULL))
}

#' @title Initialize file-based storage
#' 
#' @description In case no OS resource for storing credentials is available/
#'              implemented, a file-based fall-back is used. Sensitive
#'              information is encrypted prior to being stored to an .Rsecrets
#'              file. The key for decryption is either managed by the user
#'              or written to the user's .Rprofile.
#'
#' @param key         Key used for en-/decryption. If not user-supplied (NULL),
#'                    a new one is generated.
#' @param secretsPath Path to the .Rsecrets file (default is in user home).
#' @param profilePath Path to the .Rprofile file (default is in user home).
#'
#' @return NULL (invisibly).
#' 
initFileBasedStorage <- function (key = NULL,
                                  secretsPath = file.path("~", ".Rsecrets"),
                                  profilePath = file.path("~", ".Rprofile")) {
  # ensure that not secretr options are already set
  if (!is.null(getOption("secretr.key")) |
      !is.null(getOption("secretr.path"))) {
    stop("some or all secretr options already set. cannot init.")
  }
  # ensure that the .Rprofile does not contain any secretr info
  for (p in unique(c(profilePath, file.path("~", ".Rprofile")))) {
    if (file.exists(p)) {
      if (any(grepl("secretr\\.(key|path)", readLines(p)))) {
        stop("some secretr options already in ", p, ". cannot init.")
      }
    }
  }
  # create the vault file
  if (file.exists(secretsPath)) {
    stop("secrets file already exists. cannot init.")
  } else {
    saveRDS(list(), secretsPath)
  }
  # ensure that the openssl package is available
  if (!requireNamespace("openssl", quietly = TRUE)) {
    utils::install.packages("openssl")
    if (!requireNamespace("openssl", quietly = TRUE)) {
      stop("could not find or install the package \"openssl\". ",
           "Please do so manually.")
    }
  }
  # generate key info
  if (is.null(key)) key <- generatePassword(length = 32, symbols = FALSE)
  if (!file.exists(profilePath)) file.create(profilePath)
  # save key info to options
  options(secretr.key = key, secretr.path = secretsPath)
  # save key info to .Rprofile or pass responsibility to user
  if (interactive()) {
    message("Do you want to store key information in your .Rprofile file? ",
            "[Y/n]")
    response <- ""
    while (!response %in% c("Y", "n")) {
      response <- readline()
      if (!response %in% c("Y", "n")) message("[Y/n]")
    }
    if (response == "n") {
      message("store this information somewhere safe:\n  secretr.key = \"",
              key, "\"")
      write(paste0("\n#secretr package options\noptions(secretr.path = \"",
            secretsPath, "\")\n"), file = profilePath, append = TRUE)
    } else if (response == "Y") {
      write(paste0("\n#secretr package options\noptions(secretr.key  = \"",
                   key, "\",\n        secretr.path = \"", secretsPath,
                   "\")\n"), file = profilePath, append = TRUE)
    } else stop("unrecognized option.")
  } else {
    message("writing key information into ", profilePath,
            "\n  please remove again if this is considered not secure enough.")
    write(paste0("\n#secretr package options\noptions(secretr.key  = \"",
                 key, "\",\n        secretr.path = \"", secretsPath,
                 "\")\n"), file = profilePath, append = TRUE)
  }
  return(invisible(NULL))
}

#' @title Make file-based storage available
#' 
#' @description Ensures that all necessary infomration for file-based storage
#'              is available (secretr.path and secretr.key). If the
#'              .Rsecrets file path is not available, file-based storage is
#'              initialized and if either the key or the iv vector are not
#'              available, the user is asked for this information.
#'
#' @return NULL (invisibly).
#' 
fileBasedStorageSession <- function() {
  if (is.null(getOption("secretr.path"))) initFileBasedStorage()
  if (is.null(getOption("secretr.key"))) {
    if (interactive()) {
      message("please enter the key for secretr: ")
      options(secretr.key = readline())
    } else {
      stop("need the key for secretr.")
    }
  }
  return(invisible(NULL))
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
