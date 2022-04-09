// document.getElementById("add-alias-btn").onclick = addNewAliasField

function addNewAliasField() {
    const addNew = document.getElementById("add-alias")

    addNew.innerHTML += `<div class="div-identifier input-group">
                            <input class="other-mail" type="email" name="alias_mail" placeholder="new alias">
                            <input type="button" value="x" class="button remove-alias">
                        </div>`
}

$(document).ready(function () {
    $(document).on("click", ".remove-alias", function () {
        $(this).parent('.div-identifier').remove();
    });
});