#' @title Delete a credential item
#' 
#' @description Remove a credential item from secure storage.
#'
#' @param id The ID of the credential item to be deleted.
#'
#' @return NULL (invisibly).
#' 
#' @export
removeItem <- function(id) {
  return(removeFileBased(id))
}
