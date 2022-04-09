$(document).ready(function () {
    $(document).on("click", ".remove-alias", function () {
        $(this).parent('.div-identifier').remove();
    });

    $("#add-alias-btn").click(function(){
        $("#add-alias").append(`<div class="div-identifier input-group">
                                    <input class="other-mail" type="email" name="alias_mail" placeholder="new alias">
                                    <input type="button" value="x" class="button remove-alias">
                                </div>`)
    })
});

