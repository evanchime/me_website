document.addEventListener('DOMContentLoaded', function () {
    const logoutLink = document.getElementById('logoutLink');

    logoutLink.addEventListener('click', function (event) {
        event.preventDefault();

        // Create modal dynamically
        const modalHtml = `
        <div class="modal fade" id="logoutModal" tabindex="-1" aria-labelledby="logoutModalLabel" aria-hidden="true">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title text-center" id="logoutModalLabel">Confirm Logout</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        Are you sure you want to log out?
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary me-auto" data-bs-dismiss="modal">Cancel</button>
                        <button type="button" class="btn btn-primary" id="confirmLogout">Logout</button>
                    </div>

                </div>
            </div>
        </div>`;


        // Append modal to the body
        document.body.insertAdjacentHTML('beforeend', modalHtml);

        // Show the modal
        const logoutModal = new bootstrap.Modal(document.getElementById('logoutModal'));
        logoutModal.show();

        // Add event listener for confirm button
        document.getElementById('confirmLogout').addEventListener('click', function () {
            document.getElementById('logoutForm').submit();
        });

        // Remove the modal from the DOM after it's hidden
        logoutModal.addEventListener('hidden.bs.modal', event => {
          document.getElementById('logoutModal').remove();
        })
    });
});