document.addEventListener('DOMContentLoaded', () => {
    const readMoreLink = document.getElementById('readMoreReadLess');
    
    // Get post ID from the data attribute
    const postId = readMoreLink.dataset.postId;
    const collapseElement = document.getElementById(`post-${postId}`);

    // Rest of your code remains the same...
    collapseElement.addEventListener('show.bs.collapse', () => {
        readMoreLink.textContent = 'Read Less...';
    });

    collapseElement.addEventListener('hide.bs.collapse', () => {
        readMoreLink.textContent = 'Read More...';
    });
});