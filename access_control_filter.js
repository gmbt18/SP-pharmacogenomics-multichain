function filterstreamitem() {
    var item = getfilterstreamitem();
    var patient_data_key = item.keys[0];
    var requester_address = item.publishers[0];

    if (item.streamref === "patient_pgx_data") {
        var access_control_items = getstreamitems("access_control", { "key": patient_data_key });

        for (var i = 0; i < access_control_items.length; i++) {
            var allowed_requester = access_control_items[i].publishers[0];
            var access_status = access_control_items[i].data;

            if (allowed_requester === requester_address) {
                if (access_status === "revoked") {
                    return false;
                } else {
                    return true;
                }
            }
        }
    }

    return false;
}
