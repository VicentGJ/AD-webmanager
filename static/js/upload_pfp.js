$("#profileImage").click(function(e) {
    $("#imageUpload").click();
});

function fasterPreview( uploader ) {
    if ( uploader.files && uploader.files[0] ){
          $('#profileImage').attr('src', 
             window.URL.createObjectURL(uploader.files[0]) );
        const removepfp_btn = document.getElementById('remove-pfp')
        removepfp_btn.disabled = false
    }
}

$("#imageUpload").change(function(){
    fasterPreview( this );
});

function removepfp(){
    $('#profileImage').attr('src',
        `../../static/img/pictogram_no_users.png`);
    const removepfp_btn = document.getElementById('remove-pfp')
    removepfp_btn.disabled = true
}