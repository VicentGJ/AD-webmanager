$(document).ready(function () {
    $(document).on("click", ".flash-messages", function () {
        $(this).parent('.div-identifier').remove();
    });
})