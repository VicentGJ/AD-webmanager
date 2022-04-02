document.getElementById("select-all").onclick = selectAll

function changeButton() {
    const checkBoxes = Array.from(document.getElementsByClassName('item-to-check'))
    const deleteBtn = document.getElementById("delete-selection-btn")
    const selectAllBox = document.getElementById('select-all')
    const allSelected = checkAllSelected(checkBoxes)
    const oneSelected = checkOneSelected(checkBoxes)

    deleteBtn.disabled = !oneSelected
    selectAllBox.checked = allSelected
}
const checkAllSelected = (checkBoxes) => {
    let count = 0
    checkBoxes.map(box => box.checked ? count++ : null)
    if (count === checkBoxes.length) {
        return true
    }
    return false
}
const checkOneSelected = (checkBoxes) => {
    for (let i = 0; i < checkBoxes.length; i++) {
        if (checkBoxes[i].checked) {
            return true
        }
    }
    return false
}
function selectAll() {//    select / unsselect all items if those aren't disabled
    const deleteBtn = document.getElementById("delete-selection-btn")
    const selectAllBox = document.getElementById('select-all')
    const checkBoxes = Array.from(document.getElementsByClassName('item-to-check'))

    if (selectAllBox.checked) {
        checkBoxes.map(box => {
            if (!box.disabled) {
                box.checked = true
                deleteBtn.disabled = false

            }
        })
    } else {
        checkBoxes.map(box => {
            if (!box.disabled) {
                box.checked = false
                deleteBtn.disabled = true

            }
        })
    }
}