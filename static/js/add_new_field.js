$(document).ready(function () {
    $(document).on("click", ".remove-field", function () {
        $(this).parent('.div-identifier').remove();
    });

    $("#add-alias-btn").click(function(){
        $("#add-alias").append(`<div class="div-identifier input-group">
                                    <input class="other-mail" type="email" name="otherMailbox">
                                    <input type="button" value="-" class="button remove-field">
                                </div>`)
    })
    $("#add-home-phone-btn").click(function(){
        $("#add-home-phone").append(`<div class="div-identifier input-group">
                                    <input class="phone-field" type="text" name="otherHomePhone">
                                    <input type="button" value="-" class="button remove-field">
                                </div>`)
    })
    $("#add-mobile-phone-btn").click(function(){
        $("#add-mobile-phone").append(`<div class="div-identifier input-group">
                                    <input class="phone-field" type="text" name="otherMobile">
                                    <input type="button" value="-" class="button remove-field">
                                </div>`)
    })
    $("#add-office-phone-btn").click(function(){
        $("#add-office-phone").append(`<div class="div-identifier input-group">
                                    <input class="phone-field" type="text" name="otherTelephone">
                                    <input type="button" value="-" class="button remove-field">
                                </div>`)
    })
});

