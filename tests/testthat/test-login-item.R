context("LoginItem")

test_that("passwords can be generated", {
  expect_is(generatePassword(), "character")
  expect_equal(length(generatePassword()), 1)
  expect_equal(nchar(generatePassword(length = 15)), 15)
  expect_false(
    strsplit(generatePassword(uppercase = FALSE), split = NULL) %in% LETTERS)
})

test_that("LoginItem is created correctly", {
  cred <- LoginItem(service = "test service", username = "testuser")

  expect_is(cred, "LoginItem")
  expect_is(cred$password, "character")
  expect_equal(length(cred), 4)
  expect_match(cred$service, "test service")
  expect_match(cred$username, "testuser")
  expect_error(LoginItem(service = 123, username = "testuser"),
               "is.character(service) is not TRUE", fixed = TRUE)
})
