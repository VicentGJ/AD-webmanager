document.getElementById("add-alias-btn").onclick = addNewAliasField

function addNewAliasField() {
    const addNew = document.getElementById("add-alias")

    addNew.innerHTML += `<div class="div-identifier input-group mb-1 ">
                            <input class="form-control" type="email" name="alias_mail" placeholder="new alias" style="margin-top:10px">
                            <input type="button" value="-" class="btn btn-danger remove-alias">
                        </div>`
}

$(document).ready(function () {
    $(document).on("click", ".remove-alias", function () {
        $(this).parent('.div-identifier').remove();
    });
});