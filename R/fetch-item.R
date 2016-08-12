#' @title Fetch a credential item
#' 
#' @description Fetches a credential item from secure storage.
#'
#' @param id The ID of the requested credential item.
#'
#' @return The requested credential item.
#' 
#' @export
fetchItem <- function(id) {
  return(fetchFileBased(id))
}
