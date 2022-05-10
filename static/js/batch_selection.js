function boxClicked() {
    const checkBoxes = Array.from(document.getElementsByClassName('item-to-check'))
    const deleteBtn = document.getElementById("delete-selection-btn")
    const moveBtn = document.getElementById("move-selection-btn")
    const selectAllBox = document.getElementById('select-all')
    const allSelected = checkAllSelected(checkBoxes)
    const oneSelected = checkOneSelected(checkBoxes)

    deleteBtn.disabled = !oneSelected
    moveBtn.disabled = !oneSelected
    selectAllBox.checked = allSelected
}

const checkAllSelected = (checkBoxes) => {
    let count = 0
    let countDisabled = 0
    checkBoxes.map(box => {
        if (box.disabled) {
            countDisabled++
        }
        if (box.checked && !box.disabled) {
            count++
        }
    })
    if (count === (checkBoxes.length - countDisabled)) {
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
    const moveBtn = document.getElementById("move-selection-btn")
    const selectAllBox = document.getElementById('select-all')
    const checkBoxes = Array.from(document.getElementsByClassName('item-to-check'))

    if (selectAllBox.checked) {
        checkBoxes.map(box => {
            if (!box.disabled) {
                box.checked = true
                deleteBtn.disabled = false
                moveBtn.disabled = false
            }
        })
    } else {
        checkBoxes.map(box => {
            if (!box.disabled) {
                box.checked = false
                deleteBtn.disabled = true
                moveBtn.disabled = true
            }
        })
    }
}
document.onload = enableBatchButtons()
function enableBatchButtons() {
    const ouDelete = document.getElementById('ou-delete-btn')
    const checkBoxes = Array.from(document.getElementsByClassName('item-to-check'))
    const selectAllBox = document.getElementById('select-all')
    const batchDeleteBtn = document.getElementById("delete-selection-btn")
    const batchMoveBtn = document.getElementById("move-selection-btn")
    if (checkBoxes.length == 0) {
        ouDelete.disabled = false
        selectAllBox.style.display = "none"
        batchDeleteBtn.style.display = "none"
        batchMoveBtn.style.display = "none"
    }
}
function onMoveBtnClicked(){
    const checkBoxes = Array.from(document.getElementsByClassName('item-to-check'))
    const upperBtns = Array.from(document.getElementsByClassName('upper-element'))
    const moveHere = Array.from(document.getElementsByClassName('move-here-element'))
    const selectAllBox = document.getElementById('select-all')
    const batchDeleteBtn = document.getElementById("delete-selection-btn")
    const batchMoveBtn = document.getElementById("move-selection-btn")
    // const pasteBtn = document.getElementById("paste-selection-btn")
    const cancelPasteBtn = document.getElementById("cancel-move-btn")
    upperBtns.map(btn => {
        btn.id != "move-to-root-btn"
            ? btn.style.display = "none"
            :btn.style.display="inline"
        
    })
    checkBoxes.map(box => {
        box.checked 
            ? box.style.opacity = 0.5 
            : box.style.opacity = 0
        
        box.disabled = true
    })
    moveHere.map(element => {
        element.style.display = "inline"
        checkBoxes.map(box => {
            if(box.dataset.reference == element.dataset.reference && box.checked){
                element.disabled = true
            }
        })
        element.style.display = "inline"
    })
    selectAllBox.style.opacity = 0
    selectAllBox.disabled = true
    batchDeleteBtn.style.display = "none"
    batchMoveBtn.style.display = "none"
    // pasteBtn.style.display = "inline"
    cancelPasteBtn.style.display = "inline"

}
function cancelMove(){
    const checkBoxes = Array.from(document.getElementsByClassName('item-to-check'))
    const upperBtns = Array.from(document.getElementsByClassName('upper-element'))
    const moveHere = Array.from(document.getElementsByClassName('move-here-element'))
    const selectAllBox = document.getElementById('select-all')
    const batchDeleteBtn = document.getElementById("delete-selection-btn")
    const batchMoveBtn = document.getElementById("move-selection-btn")
    const pasteBtn = document.getElementById("paste-selection-btn")
    const cancelPasteBtn = document.getElementById("cancel-move-btn")
    upperBtns.map(btn => {
        btn.id == "move-to-root-btn"
            ? btn.style.display = "none"
            : btn.style.display = "inline"

    })
    checkBoxes.map(box => {
            box.style.opacity = 1
            // box.checked = false //keep selection checked
            box.disabled = false
    })
    moveHere.map(element => {
        element.disabled = false
        element.style.display="none"})

    selectAllBox.style.opacity = 1
    selectAllBox.disabled = false
    batchDeleteBtn.style.display = "inline"
    // batchDeleteBtn.disabled = true //selection keeps the check so theese two keep enabled
    // batchMoveBtn.disabled = true
    batchMoveBtn.style.display = "inline"
    // pasteBtn.style.display = "none"
    cancelPasteBtn.style.display = "none"
}