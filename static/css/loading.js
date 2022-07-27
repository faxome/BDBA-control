$(document).ready(function() {
    $("#btnFetch").click(function() {
      // disable button
      $(this).prop("disabled", true);
      // add spinner to button
      $(this).html(
        `<span class="spinner-grow spinner-grow-sm" role="status" aria-hidden="true"></span> Working ...`
      );
      document.getElementById("topicForm").submit()
    });
});